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

func TestWebhookBotCommandsAndReadyForReview(t *testing.T) {
	cases := []struct {
		name        string
		body        string
		wantKind    string
		wantCommand string
	}{
		{name: "force review", body: "@codespider /review", wantKind: "pr_review", wantCommand: "force_review"},
		{name: "summary", body: "@codespider /summary", wantKind: "comment_reply", wantCommand: "summary"},
		{name: "fix", body: "@codespider /fix nil check", wantKind: "comment_reply", wantCommand: "fix"},
		{name: "help", body: "@codespider /help", wantKind: "comment_reply", wantCommand: "help"},
		{name: "ask", body: "@codespider why is this safe?", wantKind: "comment_reply", wantCommand: "ask"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got *ReviewTrigger
			h := &WebhookHandler{
				BotUsername: "codespider",
				IgnoreBots:  true,
				OnTrigger: func(tr ReviewTrigger) error {
					got = &tr
					return nil
				},
			}
			payload := []byte(`{
				"action": "created",
				"is_pull": true,
				"repository": {"full_name": "acme/api"},
				"issue": {"number": 5, "title": "PR"},
				"comment": {"id": 10, "body": "` + tc.body + `", "user": {"username": "alice"}},
				"sender": {"username": "alice"}
			}`)
			req := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(payload))
			req.Header.Set("X-Gitea-Event", "issue_comment")
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != http.StatusAccepted {
				t.Fatalf("expected 202, got %d", rec.Code)
			}
			if got == nil || got.Kind != tc.wantKind || got.Command != tc.wantCommand {
				t.Fatalf("got %+v, want kind=%q command=%q", got, tc.wantKind, tc.wantCommand)
			}
		})
	}

	// Verify ready_for_review triggers PR review
	var readyTrigger *ReviewTrigger
	h := &WebhookHandler{
		BotUsername: "codespider",
		OnTrigger: func(tr ReviewTrigger) error {
			readyTrigger = &tr
			return nil
		},
	}
	req := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader([]byte(`{
		"action": "ready_for_review",
		"repository": {"full_name": "acme/api"},
		"pull_request": {"number": 8, "title": "Ready", "head": {"sha": "cafebabe"}}
	}`)))
	req.Header.Set("X-Gitea-Event", "pull_request")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted || readyTrigger == nil || readyTrigger.PRNumber != 8 {
		t.Fatalf("expected ready_for_review to trigger, code=%d trigger=%+v", rec.Code, readyTrigger)
	}

	// Verify pull_request_review_comment captures file path, line, and /ci command
	var reviewCommentTrigger *ReviewTrigger
	h2 := &WebhookHandler{
		BotUsername: "codespider",
		OnTrigger: func(tr ReviewTrigger) error {
			reviewCommentTrigger = &tr
			return nil
		},
	}
	rcReq := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader([]byte(`{
		"action": "created",
		"repository": {"full_name": "acme/api"},
		"pull_request": {"number": 12, "title": "Fix bug", "head": {"sha": "abc1234"}},
		"comment": {"id": 44, "body": "@codespider /ci", "path": "pkg/auth.go", "new_position": 27, "diff_hunk": "@@ -25,3 +25,4 @@", "user": {"username": "alice"}},
		"sender": {"username": "alice"}
	}`)))
	rcReq.Header.Set("X-Gitea-Event", "pull_request_review_comment")
	rcRec := httptest.NewRecorder()
	h2.ServeHTTP(rcRec, rcReq)
	if rcRec.Code != http.StatusAccepted || reviewCommentTrigger == nil {
		t.Fatalf("expected pull_request_review_comment to trigger, code=%d", rcRec.Code)
	}
	if reviewCommentTrigger.Command != "ci" || reviewCommentTrigger.ReviewPath != "pkg/auth.go" || reviewCommentTrigger.ReviewLine != 27 {
		t.Fatalf("unexpected review comment trigger: %+v", reviewCommentTrigger)
	}
}
