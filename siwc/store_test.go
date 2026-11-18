package siwc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type testTransport func(*http.Request) (*http.Response, error)

func (f testTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestAuthorizationUsesLoopbackPKCEAndProtectedStore(t *testing.T) {
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	urlText, err := s.Start("http://127.0.0.1:8787/api/auth/siwc/callback", "")
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(urlText)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if u.Host != "auth.openai.com" || q.Get("client_id") != "dynamic_agent_client" || q.Get("code_challenge_method") != "S256" || q.Get("state") == "" || q.Get("nonce") == "" || q.Get("code_challenge") == "" {
		t.Fatalf("invalid authorize URL: %s", u.Host)
	}
	if q.Get("redirect_uri") != "http://127.0.0.1:8787/api/auth/siwc/callback" {
		t.Fatal("wrong redirect URI")
	}
	if _, err := s.Start("http://localhost:8787/api/auth/siwc/callback", ""); err == nil {
		t.Fatal("localhost callback accepted")
	}
	info, err := os.Stat(s.path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("credential file permissions=%o", info.Mode().Perm())
	}
}

func TestConcurrentRefreshUsesRotatingTokenOnce(t *testing.T) {
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s.data.Accounts["client"] = &Credential{ClientID: "client", Subject: "subject", RefreshToken: "old-refresh", Scopes: scopes, ExpiresAt: time.Now().Add(-time.Minute)}
	s.data.Active = "client"
	refreshes := 0
	s.http = &http.Client{Transport: testTransport(func(r *http.Request) (*http.Response, error) {
		refreshes++
		if r.URL.String() != tokenURL {
			t.Errorf("unexpected URL: %s", r.URL)
		}
		if err := r.ParseForm(); err != nil {
			t.Error(err)
		}
		if r.PostForm.Get("refresh_token") != "old-refresh" {
			t.Errorf("refresh token=%q", r.PostForm.Get("refresh_token"))
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"access_token":"new-access","refresh_token":"new-refresh","expires_in":3600,"scope":"chatgpt.tokens.use.direct"}`)), Header: http.Header{}}, nil
	})}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tok, err := s.AccessToken(context.Background())
			if err != nil || tok != "new-access" {
				t.Errorf("token=%q err=%v", tok, err)
			}
		}()
	}
	wg.Wait()
	if refreshes != 1 {
		t.Fatalf("refreshes=%d", refreshes)
	}
	b, err := os.ReadFile(s.path)
	if err != nil {
		t.Fatal(err)
	}
	var stored fileState
	if err := json.Unmarshal(b, &stored); err != nil {
		t.Fatal(err)
	}
	if stored.Accounts["client"].RefreshToken != "new-refresh" {
		t.Fatal("rotating refresh token was not persisted")
	}
}

func TestCallbackValidatesIdentityBeforeSavingTokens(t *testing.T) {
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	authorize, err := s.Start("http://127.0.0.1:8787/api/auth/siwc/callback", "")
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(authorize)
	state, nonce := u.Query().Get("state"), u.Query().Get("nonce")
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	claims := jwt.MapClaims{"iss": "https://auth.openai.com", "aud": "oaiapp_test", "sub": "user_1", "email": "user@example.com", "nonce": nonce, "exp": time.Now().Add(time.Hour).Unix()}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = "test-key"
	idToken, err := tok.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	n := base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes())
	jwks, _ := json.Marshal(map[string]any{"keys": []any{map[string]string{"kty": "RSA", "kid": "test-key", "n": n, "e": e}}})
	tokenJSON, _ := json.Marshal(map[string]any{"access_token": "access", "refresh_token": "refresh", "id_token": idToken, "scope": scopes, "expires_in": 3600})
	s.http = &http.Client{Transport: testTransport(func(r *http.Request) (*http.Response, error) {
		var body string
		switch r.URL.String() {
		case tokenURL:
			if err := r.ParseForm(); err != nil {
				t.Error(err)
			}
			if r.PostForm.Get("client_id") != "oaiapp_test" || r.PostForm.Get("code_verifier") == "" || r.PostForm.Get("redirect_uri") != "http://127.0.0.1:8787/api/auth/siwc/callback" {
				t.Errorf("bad token exchange form: %#v", r.PostForm)
			}
			body = string(tokenJSON)
		case jwksURL:
			body = string(jwks)
		default:
			t.Errorf("unexpected destination: %s", r.URL)
			body = "{}"
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: http.Header{}}, nil
	})}
	if err := s.Finish(context.Background(), url.Values{"state": {"wrong"}, "code": {"code"}, "client_id": {"oaiapp_test"}}); err == nil {
		t.Fatal("invalid state was accepted")
	}
	if err := s.Finish(context.Background(), url.Values{"state": {state}, "code": {"code"}, "client_id": {"oaiapp_test"}}); err != nil {
		t.Fatal(err)
	}
	if !s.Connected() {
		t.Fatal("validated account not connected")
	}
	if got := s.Status(); len(got) != 1 || got[0].Email != "user@example.com" {
		t.Fatalf("status=%#v", got)
	}
}
