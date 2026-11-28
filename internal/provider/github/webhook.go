package github

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/Eresus-Security-OSS/CodeSpider/internal/gitea"
)

const maxWebhookBody = 10 << 20

// WebhookHandler verifies GitHub X-Hub-Signature-256 signatures and normalizes
// pull_request, issue_comment, and pull_request_review_comment events.
type WebhookHandler struct {
	Secret      string
	BotUsername string
	SkipDrafts  bool
	IgnoreBots  bool
	OnTrigger   func(gitea.ReviewTrigger) error
	OnEvent     func(eventType, outcome string)
}

func (h *WebhookHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	eventType := r.Header.Get("X-GitHub-Event")
	if h.Secret == "" {
		h.record(eventType, "rejected")
		http.Error(w, "webhook secret not configured", http.StatusUnauthorized)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxWebhookBody+1))
	if err != nil {
		h.record(eventType, "rejected")
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}
	if len(body) > maxWebhookBody {
		h.record(eventType, "rejected")
		http.Error(w, "payload too large", http.StatusRequestEntityTooLarge)
		return
	}
	if !VerifySignature(h.Secret, body, r.Header.Get("X-Hub-Signature-256")) {
		h.record(eventType, "rejected")
		http.Error(w, "invalid signature", http.StatusUnauthorized)
		return
	}
	trigger, ok, err := h.parseEvent(eventType, body)
	if err != nil {
		h.record(eventType, "rejected")
		http.Error(w, fmt.Sprintf("invalid payload: %v", err), http.StatusBadRequest)
		return
	}
	if !ok {
		h.record(eventType, "ignored")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ignored"))
		return
	}
	if h.OnTrigger != nil {
		if err := h.OnTrigger(trigger); err != nil {
			h.record(eventType, "error")
			http.Error(w, fmt.Sprintf("enqueue failed: %v", err), http.StatusInternalServerError)
			return
		}
	}
	h.record(eventType, "accepted")
	w.WriteHeader(http.StatusAccepted)
	_, _ = w.Write([]byte("accepted"))
}

func (h *WebhookHandler) record(eventType, outcome string) {
	if h.OnEvent != nil {
		h.OnEvent(eventType, outcome)
	}
}

// VerifySignature validates GitHub's sha256=<hex HMAC> webhook signature.
func VerifySignature(secret string, payload []byte, signature string) bool {
	if secret == "" || !strings.HasPrefix(signature, "sha256=") {
		return false
	}
	sig, err := hex.DecodeString(strings.TrimPrefix(signature, "sha256="))
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(payload)
	return hmac.Equal(sig, mac.Sum(nil))
}

type webhookRepository struct {
	ID       int64  `json:"id"`
	FullName string `json:"full_name"`
	CloneURL string `json:"clone_url"`
}

type pullRequestWebhook struct {
	Action      string            `json:"action"`
	Number      int64             `json:"number"`
	PullRequest pullRequest       `json:"pull_request"`
	Repository  webhookRepository `json:"repository"`
	Sender      user              `json:"sender"`
}

func (h *WebhookHandler) parseEvent(eventType string, payload []byte) (gitea.ReviewTrigger, bool, error) {
	switch eventType {
	case "pull_request":
		var ev pullRequestWebhook
		if err := json.Unmarshal(payload, &ev); err != nil {
			return gitea.ReviewTrigger{}, false, err
		}
		if !isReviewableAction(ev.Action) {
			return gitea.ReviewTrigger{}, false, nil
		}
		if h.SkipDrafts && ev.PullRequest.Draft {
			return gitea.ReviewTrigger{}, false, nil
		}
		if h.ignoredUser(ev.PullRequest.User) || h.ignoredUser(ev.Sender) {
			return gitea.ReviewTrigger{}, false, nil
		}
		owner, repo, err := splitRepo(ev.Repository.FullName)
		if err != nil {
			return gitea.ReviewTrigger{}, false, err
		}
		pr := mapPullRequest(ev.PullRequest)
		base := gitea.Repository{ID: ev.Repository.ID, FullName: ev.Repository.FullName, CloneURL: ev.Repository.CloneURL}
		isFork := isForkPR(pr, base)
		return gitea.ReviewTrigger{
			Kind: "pr_review", IsFork: isFork, Owner: owner, Repo: repo,
			CloneURL: ev.Repository.CloneURL, PRNumber: firstNumber(ev.Number, pr.Number),
			PRTitle: pr.Title, PRBody: pr.Body, BaseRef: pr.Base.Ref, HeadRef: pr.Head.Ref, HeadSHA: pr.Head.SHA,
			HeadRemoteRef: fmt.Sprintf("refs/pull/%d/head", firstNumber(ev.Number, pr.Number)),
		}, true, nil
	case "issue_comment":
		var ev struct {
			Action string `json:"action"`
			Issue  struct {
				Number int64           `json:"number"`
				Title  string          `json:"title"`
				Body   string          `json:"body"`
				PR     json.RawMessage `json:"pull_request"`
			} `json:"issue"`
			Comment struct {
				ID   int64  `json:"id"`
				Body string `json:"body"`
				User user   `json:"user"`
			} `json:"comment"`
			Repository webhookRepository `json:"repository"`
			Sender     user              `json:"sender"`
		}
		if err := json.Unmarshal(payload, &ev); err != nil {
			return gitea.ReviewTrigger{}, false, err
		}
		if ev.Action != "created" || len(ev.Issue.PR) == 0 || string(ev.Issue.PR) == "null" {
			return gitea.ReviewTrigger{}, false, nil
		}
		if h.ignoredUser(ev.Sender) || h.ignoredUser(ev.Comment.User) || !h.mentioned(ev.Comment.Body) {
			return gitea.ReviewTrigger{}, false, nil
		}
		owner, repo, err := splitRepo(ev.Repository.FullName)
		if err != nil {
			return gitea.ReviewTrigger{}, false, err
		}
		kind, command, instruction := gitea.ParseBotCommand(ev.Comment.Body, h.BotUsername)
		return gitea.ReviewTrigger{Kind: kind, Command: command, Owner: owner, Repo: repo, CloneURL: ev.Repository.CloneURL, PRNumber: ev.Issue.Number, PRTitle: ev.Issue.Title, PRBody: ev.Issue.Body, CommentID: ev.Comment.ID, CommentBy: ev.Sender.Login, Instruction: instruction}, true, nil
	case "pull_request_review_comment":
		var ev struct {
			Action      string            `json:"action"`
			PullRequest pullRequest       `json:"pull_request"`
			Repository  webhookRepository `json:"repository"`
			Sender      user              `json:"sender"`
			Comment     struct {
				ID           int64  `json:"id"`
				Body         string `json:"body"`
				Path         string `json:"path"`
				Line         int64  `json:"line"`
				OriginalLine int64  `json:"original_line"`
				DiffHunk     string `json:"diff_hunk"`
				User         user   `json:"user"`
			} `json:"comment"`
		}
		if err := json.Unmarshal(payload, &ev); err != nil {
			return gitea.ReviewTrigger{}, false, err
		}
		if ev.Action != "created" || h.ignoredUser(ev.Sender) || h.ignoredUser(ev.Comment.User) || !h.mentioned(ev.Comment.Body) {
			return gitea.ReviewTrigger{}, false, nil
		}
		owner, repo, err := splitRepo(ev.Repository.FullName)
		if err != nil {
			return gitea.ReviewTrigger{}, false, err
		}
		pr := mapPullRequest(ev.PullRequest)
		base := gitea.Repository{ID: ev.Repository.ID, FullName: ev.Repository.FullName, CloneURL: ev.Repository.CloneURL}
		isFork := isForkPR(pr, base)
		kind, command, instruction := gitea.ParseBotCommand(ev.Comment.Body, h.BotUsername)
		line := ev.Comment.Line
		if line <= 0 {
			line = ev.Comment.OriginalLine
		}
		return gitea.ReviewTrigger{Kind: kind, Command: command, IsFork: isFork, Owner: owner, Repo: repo, CloneURL: ev.Repository.CloneURL, PRNumber: pr.Number, PRTitle: pr.Title, PRBody: pr.Body, BaseRef: pr.Base.Ref, HeadRef: pr.Head.Ref, HeadSHA: pr.Head.SHA, HeadRemoteRef: fmt.Sprintf("refs/pull/%d/head", pr.Number), CommentID: ev.Comment.ID, CommentIsReview: true, CommentBy: ev.Sender.Login, Instruction: instruction, ReviewPath: ev.Comment.Path, ReviewLine: line, ReviewDiffHunk: ev.Comment.DiffHunk}, true, nil
	default:
		return gitea.ReviewTrigger{}, false, nil
	}
}

func (h *WebhookHandler) ignoredUser(u user) bool {
	if h.BotUsername != "" && strings.EqualFold(u.Login, h.BotUsername) {
		return true
	}
	return h.IgnoreBots && gitea.IsBotUser(gitea.User{Login: u.Login, Type: u.Type})
}

func (h *WebhookHandler) mentioned(body string) bool {
	return h.BotUsername == "" || strings.Contains(strings.ToLower(body), "@"+strings.ToLower(h.BotUsername))
}

func isReviewableAction(action string) bool {
	switch action {
	case "opened", "reopened", "synchronize", "ready_for_review":
		return true
	}
	return false
}

func splitRepo(fullName string) (string, string, error) {
	owner, repo, ok := strings.Cut(strings.TrimSpace(fullName), "/")
	if !ok || owner == "" || repo == "" {
		return "", "", errors.New("missing repository full_name")
	}
	return owner, repo, nil
}

func firstNumber(a, b int64) int64 {
	if a != 0 {
		return a
	}
	return b
}

func isForkPR(pr gitea.PullRequest, base gitea.Repository) bool {
	if gitea.IsForkPR(pr, base) {
		return true
	}
	if pr.Head.Repo.FullName == "" {
		// GitHub can return a null head repository for a deleted fork; fail closed.
		return true
	}
	return false
}
