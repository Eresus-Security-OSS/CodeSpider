package llm

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func captureChatBody(t *testing.T, configure func(*Client) *Client) map[string]any {
	t.Helper()
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"ok"}}],"usage":{"total_tokens":1}}`))
	}))
	defer srv.Close()

	c := configure(NewClient(srv.URL, "k", "m", 5*time.Second))
	if _, err := c.Chat(context.Background(), []Message{{Role: "user", Content: "hi"}}, nil); err != nil {
		t.Fatal(err)
	}
	return got
}

func TestReasoningEffortIsSentOnlyWhenConfigured(t *testing.T) {
	with := captureChatBody(t, func(c *Client) *Client { return c.WithReasoningEffort(" none ") })
	if with["reasoning_effort"] != "none" {
		t.Fatalf("expected trimmed reasoning_effort=none in the request, got %v", with["reasoning_effort"])
	}

	without := captureChatBody(t, func(c *Client) *Client { return c })
	if _, present := without["reasoning_effort"]; present {
		t.Fatalf("reasoning_effort must be omitted when unset, got %v", without["reasoning_effort"])
	}

	// A per-request model override must keep the configured effort.
	over := captureChatBody(t, func(c *Client) *Client { return c.WithReasoningEffort("low").WithModel("other") })
	if over["reasoning_effort"] != "low" || over["model"] != "other" {
		t.Fatalf("WithModel must preserve reasoning effort, got %v", over)
	}
}
