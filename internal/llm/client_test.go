package llm

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestChatRetriesTransientErrors(t *testing.T) {
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := attempts.Add(1)
		if n == 1 {
			w.Header().Set("Retry-After", "0")
			http.Error(w, "rate limited", http.StatusTooManyRequests)
			return
		}
		if n == 2 {
			http.Error(w, "upstream busy", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []any{map[string]any{
				"message": map[string]any{
					"role":    "assistant",
					"content": "all good",
				},
			}},
			"usage": map[string]any{"total_tokens": 42},
		})
	}))
	defer srv.Close()

	client := NewClient(srv.URL, "sk-test-secret", "gpt-5", 2*time.Second).WithRetry(2, 5*time.Millisecond)
	resp, err := client.Chat(context.Background(), []Message{{Role: "user", Content: "hi"}}, nil)
	if err != nil {
		t.Fatalf("expected retry recovery, got error: %v", err)
	}
	if resp.Message.Content != "all good" || resp.Usage.TotalTokens != 42 {
		t.Fatalf("unexpected response: %+v", resp)
	}
	if attempts.Load() != 3 {
		t.Fatalf("expected 3 attempts, got %d", attempts.Load())
	}
}

func TestChatDoesNotRetryAuthFailureAndRedactsKey(t *testing.T) {
	var attempts atomic.Int32
	secret := "sk-super-secret-key"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		http.Error(w, "invalid key: "+secret, http.StatusUnauthorized)
	}))
	defer srv.Close()

	client := NewClient(srv.URL, secret, "gpt-5", 2*time.Second).WithRetry(3, 5*time.Millisecond)
	_, err := client.Chat(context.Background(), []Message{{Role: "user", Content: "hi"}}, nil)
	if err == nil {
		t.Fatal("expected error on 401")
	}
	if attempts.Load() != 1 {
		t.Fatalf("expected no retry on 401, got %d attempts", attempts.Load())
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("API key leaked in error: %v", err)
	}
}

func TestChatCancelsDuringBackoff(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "busy", http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	client := NewClient(srv.URL, "k", "m", 2*time.Second).WithRetry(3, 200*time.Millisecond)
	_, err := client.Chat(ctx, []Message{{Role: "user", Content: "hi"}}, nil)
	if err == nil {
		t.Fatal("expected context deadline error")
	}
}
