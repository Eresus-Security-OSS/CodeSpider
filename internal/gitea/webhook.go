package gitea

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
)

// ReviewTrigger represents a normalized event that schedules an agent run.
type ReviewTrigger struct {
	Kind             string // "pr_review" or "comment_reply"
	Owner            string
	Repo             string
	CloneURL         string
	PRNumber         int64
	PRTitle          string
	PRBody           string
	BaseRef          string
	HeadRef          string
	HeadSHA          string
	CommentID        int64
	CommentBy        string
	Instruction      string
	RepoInstructions string
}

// WebhookHandler verifies Gitea webhooks and dispatches normalized triggers.
type WebhookHandler struct {
	Secret      string
	BotUsername string
	SkipDrafts  bool
	IgnoreBots  bool
	OnTrigger   func(ReviewTrigger) error
}

// ServeHTTP handles incoming Gitea webhook HTTP requests.
func (h *WebhookHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 10<<20))
	if err != nil {
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}

	if h.Secret != "" {
		sig := r.Header.Get("X-Gitea-Signature")
		if !VerifySignature(h.Secret, body, sig) {
			http.Error(w, "invalid signature", http.StatusUnauthorized)
			return
		}
	}

	eventType := r.Header.Get("X-Gitea-Event")
	trigger, ok, err := h.parseEvent(eventType, body)
	if err != nil {
		http.Error(w, fmt.Sprintf("invalid payload: %v", err), http.StatusBadRequest)
		return
	}
	if !ok {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ignored"))
		return
	}

	if h.OnTrigger != nil {
		if err := h.OnTrigger(trigger); err != nil {
			http.Error(w, fmt.Sprintf("enqueue failed: %v", err), http.StatusInternalServerError)
			return
		}
	}

	w.WriteHeader(http.StatusAccepted)
	_, _ = w.Write([]byte("accepted"))
}

// VerifySignature validates a Gitea HMAC-SHA256 webhook signature.
func VerifySignature(secret string, payload []byte, signatureHex string) bool {
	if secret == "" || signatureHex == "" {
		return false
	}
	sig, err := hex.DecodeString(strings.TrimSpace(signatureHex))
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	expected := mac.Sum(nil)
	return hmac.Equal(sig, expected)
}

func (h *WebhookHandler) parseEvent(eventType string, payload []byte) (ReviewTrigger, bool, error) {
	switch eventType {
	case "pull_request":
		var ev PullRequestEvent
		if err := json.Unmarshal(payload, &ev); err != nil {
			return ReviewTrigger{}, false, err
		}
		if !isReviewablePRAction(ev.Action) {
			return ReviewTrigger{}, false, nil
		}
		if h.SkipDrafts && isDraftPR(ev.PullRequest) {
			return ReviewTrigger{}, false, nil
		}
		prAuthor := firstNonEmpty(ev.PullRequest.User.Username, ev.PullRequest.User.Login)
		sender := firstNonEmpty(ev.Sender.Username, ev.Sender.Login)
		if h.BotUsername != "" && (strings.EqualFold(prAuthor, h.BotUsername) || strings.EqualFold(sender, h.BotUsername)) {
			return ReviewTrigger{}, false, nil
		}
		if h.IgnoreBots && (isBotUser(ev.PullRequest.User) || isBotUser(ev.Sender)) {
			return ReviewTrigger{}, false, nil
		}
		owner, repo := splitFullName(ev.Repository.FullName)
		if owner == "" || repo == "" {
			return ReviewTrigger{}, false, errors.New("missing repository full_name")
		}
		return ReviewTrigger{
			Kind:     "pr_review",
			Owner:    owner,
			Repo:     repo,
			CloneURL: ev.Repository.CloneURL,
			PRNumber: ev.PullRequest.Number,
			PRTitle:  ev.PullRequest.Title,
			PRBody:   ev.PullRequest.Body,
			BaseRef:  ev.PullRequest.Base.Ref,
			HeadRef:  ev.PullRequest.Head.Ref,
			HeadSHA:  ev.PullRequest.Head.SHA,
		}, true, nil

	case "issue_comment", "pull_request_comment":
		var ev IssueCommentEvent
		if err := json.Unmarshal(payload, &ev); err != nil {
			return ReviewTrigger{}, false, err
		}
		if ev.Action != "created" {
			return ReviewTrigger{}, false, nil
		}
		// Ignore comments authored by the bot itself to prevent infinite loops.
		sender := firstNonEmpty(ev.Sender.Username, ev.Sender.Login, ev.Comment.User.Username, ev.Comment.User.Login)
		if h.BotUsername != "" && strings.EqualFold(sender, h.BotUsername) {
			return ReviewTrigger{}, false, nil
		}
		if !ev.IsPull && ev.Issue.PullRequest == nil {
			return ReviewTrigger{}, false, nil
		}
		if h.BotUsername != "" && !strings.Contains(strings.ToLower(ev.Comment.Body), "@"+strings.ToLower(h.BotUsername)) {
			return ReviewTrigger{}, false, nil
		}
		owner, repo := splitFullName(ev.Repository.FullName)
		if owner == "" || repo == "" {
			return ReviewTrigger{}, false, errors.New("missing repository full_name")
		}
		return ReviewTrigger{
			Kind:        "comment_reply",
			Owner:       owner,
			Repo:        repo,
			CloneURL:    ev.Repository.CloneURL,
			PRNumber:    ev.Issue.Number,
			PRTitle:     ev.Issue.Title,
			PRBody:      ev.Issue.Body,
			CommentID:   ev.Comment.ID,
			CommentBy:   sender,
			Instruction: ev.Comment.Body,
		}, true, nil

	default:
		return ReviewTrigger{}, false, nil
	}
}

func isReviewablePRAction(action string) bool {
	switch action {
	case "opened", "reopened", "synchronized", "synchronize":
		return true
	default:
		return false
	}
}

func splitFullName(full string) (string, string) {
	parts := strings.SplitN(strings.TrimSpace(full), "/", 2)
	if len(parts) != 2 {
		return "", ""
	}
	return parts[0], parts[1]
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func isDraftPR(pr PullRequest) bool {
	if pr.Draft {
		return true
	}
	upper := strings.ToUpper(strings.TrimSpace(pr.Title))
	return strings.HasPrefix(upper, "WIP:") || strings.HasPrefix(upper, "[WIP]")
}

func isBotUser(u User) bool {
	if strings.EqualFold(strings.TrimSpace(u.Type), "Bot") {
		return true
	}
	name := strings.ToLower(strings.TrimSpace(firstNonEmpty(u.Username, u.Login)))
	return strings.HasSuffix(name, "[bot]")
}
