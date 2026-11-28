package github

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Eresus-Security-OSS/CodeSpider/internal/gitea"
)

func signedGitHubRequest(secret, event string, payload []byte) *http.Request {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(payload)
	req := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(payload))
	req.Header.Set("X-GitHub-Event", event)
	req.Header.Set("X-Hub-Signature-256", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	return req
}

func TestGitHubWebhookNormalizesPullRequest(t *testing.T) {
	const secret = "webhook-key"
	payload := []byte(`{"action":"opened","number":12,"repository":{"id":10,"full_name":"acme/app","clone_url":"https://github.com/acme/app.git"},"sender":{"login":"alice","type":"User"},"pull_request":{"number":12,"title":"Add feature","body":"details","draft":false,"user":{"login":"alice","type":"User"},"base":{"ref":"main","sha":"base","repo":{"id":10,"full_name":"acme/app","clone_url":"https://github.com/acme/app.git"}},"head":{"ref":"feature","sha":"head","repo":{"id":20,"full_name":"alice/app","clone_url":"https://github.com/alice/app.git"}}}}`)
	var got gitea.ReviewTrigger
	h := &WebhookHandler{Secret: secret, BotUsername: "codespider", SkipDrafts: true, IgnoreBots: true, OnTrigger: func(trigger gitea.ReviewTrigger) error { got = trigger; return nil }}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, signedGitHubRequest(secret, "pull_request", payload))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	if got.Kind != "pr_review" || got.Owner != "acme" || got.Repo != "app" || got.PRNumber != 12 || got.HeadSHA != "head" || got.BaseRef != "main" || !got.IsFork {
		t.Fatalf("unexpected trigger: %+v", got)
	}
}

func TestGitHubWebhookMentionCommentAndSignature(t *testing.T) {
	const secret = "webhook-key"
	payload := []byte(`{"action":"created","issue":{"number":5,"title":"Fix","pull_request":{"url":"https://api.github.com/repos/acme/app/pulls/5"}},"comment":{"id":99,"body":"@codespider /summary please","user":{"login":"alice","type":"User"}},"repository":{"full_name":"acme/app","clone_url":"https://github.com/acme/app.git"},"sender":{"login":"alice","type":"User"}}`)
	var got gitea.ReviewTrigger
	h := &WebhookHandler{Secret: secret, BotUsername: "codespider", OnTrigger: func(trigger gitea.ReviewTrigger) error { got = trigger; return nil }}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, signedGitHubRequest(secret, "issue_comment", payload))
	if rec.Code != http.StatusAccepted || got.Command != "summary" || got.CommentID != 99 || got.Kind != "comment_reply" {
		t.Fatalf("status=%d trigger=%+v body=%s", rec.Code, got, rec.Body.String())
	}
	bad := signedGitHubRequest(secret, "issue_comment", payload)
	bad.Header.Set("X-Hub-Signature-256", "sha256="+strings.Repeat("0", 64))
	badRec := httptest.NewRecorder()
	h.ServeHTTP(badRec, bad)
	if badRec.Code != http.StatusUnauthorized {
		t.Fatalf("invalid signature status=%d", badRec.Code)
	}
}

func TestGitHubWebhookSkipsDraftAndRejectsOversize(t *testing.T) {
	const secret = "webhook-key"
	h := &WebhookHandler{Secret: secret, SkipDrafts: true}
	draft := []byte(`{"action":"opened","number":1,"repository":{"full_name":"acme/app"},"pull_request":{"number":1,"draft":true}}`)
	draftRec := httptest.NewRecorder()
	h.ServeHTTP(draftRec, signedGitHubRequest(secret, "pull_request", draft))
	if draftRec.Code != http.StatusOK {
		t.Fatalf("draft status=%d", draftRec.Code)
	}
	large := []byte(`{"action":"opened","padding":"` + strings.Repeat("x", maxWebhookBody) + `"}`)
	largeRec := httptest.NewRecorder()
	h.ServeHTTP(largeRec, signedGitHubRequest(secret, "pull_request", large))
	if largeRec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("large payload status=%d", largeRec.Code)
	}
}
