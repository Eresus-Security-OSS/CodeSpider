package gitea

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"
)

func signPayload(secret string, payload []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}

func TestWebhookPullRequestTrigger(t *testing.T) {
	secret := "top-secret"
	payload := []byte(`{
		"action": "opened",
		"number": 42,
		"repository": {"full_name": "acme/api", "clone_url": "https://gitea.local/acme/api.git"},
		"pull_request": {
			"number": 42,
			"title": "Fix auth",
			"base": {"ref": "main"},
			"head": {"ref": "fix-auth", "sha": "deadbeef"}
		}
	}`)

	var got *ReviewTrigger
	h := &WebhookHandler{
		Secret:      secret,
		BotUsername: "codespider",
		OnTrigger: func(tr ReviewTrigger) error {
			got = &tr
			return nil
		},
	}

	req := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(payload))
	req.Header.Set("X-Gitea-Event", "pull_request")
	req.Header.Set("X-Gitea-Signature", signPayload(secret, payload))
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d: %s", rec.Code, rec.Body.String())
	}
	if got == nil || got.PRNumber != 42 || got.HeadSHA != "deadbeef" || got.Kind != "pr_review" {
		t.Fatalf("unexpected trigger: %+v", got)
	}
}

func TestWebhookRejectsBadSignature(t *testing.T) {
	h := &WebhookHandler{Secret: "top-secret"}
	req := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader([]byte(`{}`)))
	req.Header.Set("X-Gitea-Event", "pull_request")
	req.Header.Set("X-Gitea-Signature", "0000")
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestWebhookIgnoresBotSelfComment(t *testing.T) {
	payload := []byte(`{
		"action": "created",
		"is_pull": true,
		"repository": {"full_name": "acme/api"},
		"issue": {"number": 7, "title": "PR"},
		"comment": {"id": 99, "body": "@codespider hello", "user": {"username": "codespider"}},
		"sender": {"username": "codespider"}
	}`)

	triggered := false
	h := &WebhookHandler{
		BotUsername: "codespider",
		OnTrigger: func(tr ReviewTrigger) error {
			triggered = true
			return nil
		},
	}

	req := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(payload))
	req.Header.Set("X-Gitea-Event", "issue_comment")
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 ignored, got %d", rec.Code)
	}
	if triggered {
		t.Fatal("expected bot self-comment to be ignored")
	}
}

func TestWebhookSkipsDraftAndBotPRs(t *testing.T) {
	cases := []struct {
		name    string
		payload string
	}{
		{
			name: "draft flag",
			payload: `{
				"action": "opened",
				"repository": {"full_name": "acme/api"},
				"pull_request": {"number": 10, "title": "Add feature", "draft": true, "head": {"sha": "abc"}}
			}`,
		},
		{
			name: "wip title",
			payload: `{
				"action": "opened",
				"repository": {"full_name": "acme/api"},
				"pull_request": {"number": 11, "title": "[WIP] Refactor", "head": {"sha": "abc"}}
			}`,
		},
		{
			name: "bot user type",
			payload: `{
				"action": "opened",
				"repository": {"full_name": "acme/api"},
				"pull_request": {"number": 12, "title": "Bump deps", "user": {"username": "renovate", "type": "Bot"}, "head": {"sha": "abc"}}
			}`,
		},
		{
			name: "bot suffix",
			payload: `{
				"action": "opened",
				"repository": {"full_name": "acme/api"},
				"pull_request": {"number": 13, "title": "Bump deps", "user": {"username": "dependabot[bot]"}, "head": {"sha": "abc"}}
			}`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			triggered := false
			h := &WebhookHandler{
				BotUsername: "codespider",
				SkipDrafts:  true,
				IgnoreBots:  true,
				OnTrigger: func(tr ReviewTrigger) error {
					triggered = true
					return nil
				},
			}
			req := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader([]byte(tc.payload)))
			req.Header.Set("X-Gitea-Event", "pull_request")
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("expected 200 ignored, got %d", rec.Code)
			}
			if triggered {
				t.Fatalf("expected %s PR to be skipped", tc.name)
			}
		})
	}
}
