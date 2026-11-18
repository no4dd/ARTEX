// Package siwc manages a local Sign in with ChatGPT session for ARTEX.
// Credentials never pass through the browser-facing ARTEX API.
package siwc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

const (
	authorizeURL = "https://auth.openai.com/api/accounts/authorize"
	tokenURL     = "https://auth.openai.com/api/accounts/oauth/token"
	jwksURL      = "https://auth.openai.com/.well-known/jwks.json"
	resource     = "https://api.openai.com/v1"
	scopes       = "openid profile email offline_access resource.invoke chatgpt.tokens.use.direct"
)

type Credential struct {
	Email        string    `json:"email"`
	Subject      string    `json:"subject"`
	ClientID     string    `json:"client_id"`
	IDToken      string    `json:"id_token,omitempty"`
	AccessToken  string    `json:"access_token,omitempty"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	Scopes       string    `json:"scopes,omitempty"`
	ExpiresAt    time.Time `json:"expires_at,omitempty"`
}

type fileState struct {
	HostID       string                 `json:"host_id"`
	Active       string                 `json:"active"`
	CyberProgram string                 `json:"cyber_program,omitempty"`
	Accounts     map[string]*Credential `json:"accounts"`
}

type pending struct {
	State       string
	Nonce       string
	Verifier    string
	RedirectURI string
	ClientID    string
	ExpiresAt   time.Time
}

type Store struct {
	mu      sync.Mutex
	path    string
	http    *http.Client
	data    fileState
	pending *pending
}

func New(keyDir string) (*Store, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	s := &Store{path: filepath.Join(keyDir, "chatgpt-plan.json"), http: &http.Client{Timeout: 15 * time.Second, Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	if b, err := os.ReadFile(s.path); err == nil {
		if err := json.Unmarshal(b, &s.data); err != nil {
			return nil, fmt.Errorf("read ChatGPT session: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if s.data.HostID == "" {
		s.data.HostID = "urn:uuid:" + uuid.NewString()
	}
	if s.data.Accounts == nil {
		s.data.Accounts = map[string]*Credential{}
	}
	if err := s.saveLocked(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) saveLocked() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".chatgpt-plan-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), s.path)
}

func randomString() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Start creates an authorization attempt. The caller must present the returned
// URL to the user's system browser, never write it to logs.
func (s *Store) Start(callbackURI, clientID string) (string, error) {
	u, err := url.Parse(callbackURI)
	if err != nil || u.Scheme != "http" || u.Hostname() != "127.0.0.1" || u.Path != "/api/auth/siwc/callback" {
		return "", errors.New("ChatGPT callback must be the local ARTEX callback")
	}
	state, err := randomString()
	if err != nil {
		return "", err
	}
	nonce, err := randomString()
	if err != nil {
		return "", err
	}
	verifier, err := randomString()
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if clientID != "" && s.data.Accounts[clientID] == nil {
		return "", errors.New("unknown ChatGPT account")
	}
	requestedID := clientID
	if requestedID == "" {
		requestedID = "dynamic_agent_client"
	}
	s.pending = &pending{State: state, Nonce: nonce, Verifier: verifier, RedirectURI: callbackURI, ClientID: clientID, ExpiresAt: time.Now().Add(10 * time.Minute)}
	q := url.Values{"client_id": {requestedID}, "ext_agent_host_id": {s.data.HostID}, "response_type": {"code"}, "redirect_uri": {callbackURI}, "scope": {scopes}, "resource": {resource}, "state": {state}, "nonce": {nonce}, "code_challenge_method": {"S256"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(sum256(verifier))}}
	if clientID == "" {
		q.Set("agent_name_hint", "ARTEX")
	} else if c := s.data.Accounts[clientID]; c != nil {
		if c.Email != "" {
			q.Set("login_hint", c.Email)
		}
		if !hasScope(c.Scopes, "chatgpt.tokens.use.direct") {
			q.Set("prompt", "consent")
		}
	}
	return authorizeURL + "?" + q.Encode(), nil
}

func sum256(v string) []byte { h := sha256.Sum256([]byte(v)); return h[:] }

type tokenReply struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	TokenType    string `json:"token_type"`
	Scope        string `json:"scope"`
	ExpiresIn    int    `json:"expires_in"`
}

func (s *Store) exchange(ctx context.Context, form url.Values) (tokenReply, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return tokenReply{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := s.http.Do(req)
	if err != nil {
		return tokenReply{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return tokenReply{}, fmt.Errorf("OpenAI token exchange returned HTTP %d", resp.StatusCode)
	}
	var t tokenReply
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&t); err != nil {
		return t, err
	}
	if t.AccessToken == "" {
		return t, errors.New("OpenAI token response has no access token")
	}
	if t.ExpiresIn <= 0 || (t.TokenType != "" && !strings.EqualFold(t.TokenType, "Bearer")) {
		return t, errors.New("OpenAI token response has invalid lifetime or token type")
	}
	return t, nil
}

// Finish validates state, exchanges the authorization code, verifies the signed
// ID token, and only then replaces the selected account's credentials.
func (s *Store) Finish(ctx context.Context, q url.Values) error {
	s.mu.Lock()
	p := s.pending
	if p == nil || time.Now().After(p.ExpiresAt) || q.Get("state") == "" || q.Get("state") != p.State {
		s.mu.Unlock()
		return errors.New("invalid or expired ChatGPT sign-in state")
	}
	s.pending = nil
	s.mu.Unlock()
	if q.Get("error") != "" {
		return fmt.Errorf("ChatGPT authorization was not granted: %s", q.Get("error"))
	}
	if q.Get("code") == "" {
		return errors.New("ChatGPT callback has no authorization code")
	}
	clientID := p.ClientID
	if clientID == "" {
		clientID = q.Get("client_id")
		if clientID == "" || clientID == "dynamic_agent_client" {
			return errors.New("ChatGPT registration returned no issued client ID")
		}
	} else if got := q.Get("client_id"); got != "" && got != clientID {
		return errors.New("ChatGPT callback client ID changed")
	}
	t, err := s.exchange(ctx, url.Values{"grant_type": {"authorization_code"}, "client_id": {clientID}, "code": {q.Get("code")}, "code_verifier": {p.Verifier}, "redirect_uri": {p.RedirectURI}, "resource": {resource}})
	if err != nil {
		return err
	}
	if t.IDToken == "" {
		return errors.New("OpenAI returned no ID token")
	}
	subject, email, err := s.verifyIDToken(ctx, t.IDToken, clientID, p.Nonce)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if old := s.data.Accounts[clientID]; old != nil && old.Subject != subject {
		return errors.New("ChatGPT account identity changed")
	}
	if t.RefreshToken == "" {
		return errors.New("OpenAI returned no renewable session")
	}
	s.data.Accounts[clientID] = &Credential{Email: email, Subject: subject, ClientID: clientID, IDToken: t.IDToken, AccessToken: t.AccessToken, RefreshToken: t.RefreshToken, Scopes: t.Scope, ExpiresAt: time.Now().Add(time.Duration(t.ExpiresIn) * time.Second)}
	s.data.Active = clientID
	return s.saveLocked()
}

func hasScope(scopes, want string) bool {
	for _, v := range strings.Fields(scopes) {
		if v == want {
			return true
		}
	}
	return false
}

func (s *Store) Connected() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.data.Accounts[s.data.Active]
	return c != nil && c.RefreshToken != "" && hasScope(c.Scopes, "chatgpt.tokens.use.direct")
}

func (s *Store) CyberProgram() string { s.mu.Lock(); defer s.mu.Unlock(); return s.data.CyberProgram }
func (s *Store) SetCyberProgram(program string) error {
	if program != "" && program != "daybreak_blue" {
		return errors.New("unsupported Daybreak program")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data.CyberProgram = program
	return s.saveLocked()
}

type AccountStatus struct {
	ClientID  string `json:"client_id"`
	Email     string `json:"email"`
	Active    bool   `json:"active"`
	Connected bool   `json:"connected"`
}

func (s *Store) Status() []AccountStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]AccountStatus, 0, len(s.data.Accounts))
	for id, c := range s.data.Accounts {
		out = append(out, AccountStatus{ClientID: id, Email: c.Email, Active: id == s.data.Active, Connected: c.RefreshToken != "" && hasScope(c.Scopes, "chatgpt.tokens.use.direct")})
	}
	return out
}

// AccessToken serializes refreshes so a rotating refresh token is never reused
// by two ARTEX workers. A missing grant fails closed.
func (s *Store) AccessToken(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.data.Accounts[s.data.Active]
	if c == nil || c.RefreshToken == "" || !hasScope(c.Scopes, "chatgpt.tokens.use.direct") {
		return "", errors.New("connect a ChatGPT plan in ARTEX settings")
	}
	if c.AccessToken != "" && time.Until(c.ExpiresAt) > time.Minute {
		return c.AccessToken, nil
	}
	t, err := s.exchange(ctx, url.Values{"grant_type": {"refresh_token"}, "client_id": {c.ClientID}, "refresh_token": {c.RefreshToken}, "resource": {resource}})
	if err != nil {
		return "", err
	}
	if t.RefreshToken == "" {
		return "", errors.New("OpenAI refresh returned no replacement refresh token")
	}
	if t.Scope != "" && !hasScope(t.Scope, "chatgpt.tokens.use.direct") {
		return "", errors.New("ChatGPT plan permission was revoked")
	}
	c.AccessToken = t.AccessToken
	c.RefreshToken = t.RefreshToken
	c.ExpiresAt = time.Now().Add(time.Duration(t.ExpiresIn) * time.Second)
	if t.Scope != "" {
		c.Scopes = t.Scope
	}
	if err := s.saveLocked(); err != nil {
		return "", err
	}
	return c.AccessToken, nil
}

// Models returns the signed-in account's visible model slugs in server order.
func (s *Store) Models(ctx context.Context) ([]string, error) {
	token, err := s.AccessToken(ctx)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, resource+"/models", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := s.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("OpenAI model list returned HTTP %d", resp.StatusCode)
	}
	var result struct {
		Models []struct {
			Slug       string `json:"slug"`
			Visibility string `json:"visibility"`
		} `json:"models"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&result); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(result.Models))
	for _, m := range result.Models {
		if m.Visibility == "list" && m.Slug != "" {
			out = append(out, m.Slug)
		}
	}
	return out, nil
}

func (s *Store) Select(clientID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.data.Accounts[clientID] == nil {
		return errors.New("unknown ChatGPT account")
	}
	s.data.Active = clientID
	return s.saveLocked()
}

func (s *Store) SignOut(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.data.Accounts[s.data.Active]
	if c == nil {
		return nil
	}
	var revokeErr error
	if c.RefreshToken != "" {
		form := url.Values{"token": {c.RefreshToken}, "token_type_hint": {"refresh_token"}, "client_id": {c.ClientID}}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://auth.openai.com/api/accounts/oauth/revoke", strings.NewReader(form.Encode()))
		if err == nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			var resp *http.Response
			resp, err = s.http.Do(req)
			if err == nil {
				resp.Body.Close()
				if resp.StatusCode != 200 {
					err = fmt.Errorf("revocation returned HTTP %d", resp.StatusCode)
				}
			}
		}
		revokeErr = err
	}
	c.AccessToken = ""
	c.RefreshToken = ""
	c.IDToken = ""
	c.ExpiresAt = time.Time{}
	if err := s.saveLocked(); err != nil {
		return err
	}
	return revokeErr
}

type idClaims struct {
	Email string `json:"email"`
	Nonce string `json:"nonce"`
	jwt.RegisteredClaims
}

func (s *Store) verifyIDToken(ctx context.Context, raw, clientID, nonce string) (string, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURL, nil)
	if err != nil {
		return "", "", err
	}
	resp, err := s.http.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", "", fmt.Errorf("OpenAI JWKS returned HTTP %d", resp.StatusCode)
	}
	var keys struct {
		Keys []struct {
			Kty string `json:"kty"`
			Kid string `json:"kid"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&keys); err != nil {
		return "", "", err
	}
	claims := &idClaims{}
	tok, err := jwt.ParseWithClaims(raw, claims, func(t *jwt.Token) (any, error) {
		if t.Method.Alg() != "RS256" {
			return nil, errors.New("unexpected ID token signature algorithm")
		}
		kid, _ := t.Header["kid"].(string)
		for _, k := range keys.Keys {
			if k.Kid != kid || k.Kty != "RSA" {
				continue
			}
			nb, e1 := base64.RawURLEncoding.DecodeString(k.N)
			eb, e2 := base64.RawURLEncoding.DecodeString(k.E)
			if e1 != nil || e2 != nil {
				return nil, errors.New("invalid JWKS key")
			}
			return &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: int(new(big.Int).SetBytes(eb).Int64())}, nil
		}
		return nil, errors.New("ID token signing key not found")
	}, jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuer("https://auth.openai.com"), jwt.WithAudience(clientID), jwt.WithExpirationRequired())
	if err != nil || !tok.Valid {
		return "", "", fmt.Errorf("invalid OpenAI ID token: %w", err)
	}
	if claims.Nonce != nonce || claims.Subject == "" {
		return "", "", errors.New("OpenAI ID token nonce or subject mismatch")
	}
	return claims.Subject, claims.Email, nil
}
