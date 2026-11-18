package agent

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestChatGPTPlanTransportPinsEndpointAndShapesRequest(t *testing.T) {
	called := 0
	transport := planTransport{
		token: func(context.Context) (string, error) { called++; return "short-lived-token", nil },
		cyber: "daybreak_blue",
		base: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if got := r.Header.Get("Authorization"); got != "Bearer short-lived-token" {
				t.Errorf("authorization=%q", got)
			}
			if r.URL.String() != "https://api.openai.com/v1/responses" {
				t.Errorf("destination=%s", r.URL)
			}
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body["store"] != false || body["stream"] != true {
				t.Errorf("plan flags: %#v", body)
			}
			if _, ok := body["max_output_tokens"]; ok {
				t.Error("unsupported max_output_tokens was sent")
			}
			if _, ok := body["temperature"]; ok {
				t.Error("unsupported temperature was sent")
			}
			tools, ok := body["tools"].([]any)
			if !ok || len(tools) != 1 {
				t.Fatalf("tools=%#v", body["tools"])
			}
			ns := tools[0].(map[string]any)
			if ns["type"] != "namespace" || ns["name"] != "artex" {
				t.Errorf("namespace=%#v", ns)
			}
			input := body["input"].([]any)[0].(map[string]any)
			if input["namespace"] != "artex" || input["name"] != "terminal" {
				t.Errorf("history=%#v", input)
			}
			output := body["input"].([]any)[1].(map[string]any)
			if output["namespace"] != "artex" {
				t.Errorf("tool output=%#v", output)
			}
			if body["access_programs"].(map[string]any)["cyber"] != "daybreak_blue" {
				t.Errorf("daybreak=%#v", body["access_programs"])
			}
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("ok")), Header: http.Header{}}, nil
		}),
	}
	r, err := http.NewRequest(http.MethodPost, "https://api.openai.com/v1/responses", strings.NewReader(`{"model":"gpt-6-sol","store":true,"stream":false,"max_output_tokens":800,"temperature":0.1,"tools":[{"type":"function","name":"terminal"}],"input":[{"type":"function_call","name":"terminal","call_id":"call_1","arguments":"{}"},{"type":"function_call_output","call_id":"call_1","output":"ok"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := transport.RoundTrip(r)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if called != 1 {
		t.Fatalf("token source called %d times", called)
	}
	r.URL.Host = "other.example"
	if _, err := transport.RoundTrip(r); err == nil {
		t.Error("wrong endpoint was allowed")
	}
	if called != 1 {
		t.Error("wrong endpoint requested an OAuth token")
	}
}
