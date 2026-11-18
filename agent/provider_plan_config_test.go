package agent

import "testing"

func TestConfigFromChatGPTPlanPinsEndpointAndCredential(t *testing.T) {
	c := ConfigFrom("chatgpt-plan", "gpt-6-sol", "https://untrusted.example/v1", "secret", "http://proxy.example")
	if c.Format != FormatChatGPTPlan || c.Provider() != "chatgpt-plan" {
		t.Fatalf("wrong provider format: %q", c.Format)
	}
	if c.BaseURL != "https://api.openai.com/v1" || c.APIKey != "" || c.Proxy != "" {
		t.Fatalf("plan config did not pin endpoint and clear credentials: %+v", c)
	}
	if c.NeedsAPIKey() {
		t.Fatal("ChatGPT plan config unexpectedly needs an API key")
	}
}
