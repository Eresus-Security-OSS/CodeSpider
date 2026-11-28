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
	Kind               string // "pr_review" or "comment_reply"
	Command            string // "", "force_review", "summary", "fix", "help", "ask", "ci", "redteam"
	DryRun             bool
	Offline            bool
	IsFork             bool
	Owner              string
	Repo               string
	CloneURL           string
	PRNumber           int64
	PRTitle            string
	PRBody             string
	BaseRef            string
	HeadRef            string
	HeadSHA            string
	HeadRemoteRef      string
	PreviousSHA        string
	CommentID          int64
	CommentIsReview    bool
	CommentBy          string
	Instruction        string
	ReviewPath         string
	ReviewLine         int64
	ReviewDiffHunk     string
	SecretAlerts       string
	DeterministicBrief string
	MemoryContext      string
	RepoInstructions   string
	RepoSkills         []string
	RepoModel          string
	DiffLineCount      int
}

// WebhookHandler verifies Gitea webhooks and dispatches normalized triggers.
type WebhookHandler struct {
	Secret        string
	RequireSecret bool
	BotUsername   string
	SkipDrafts    bool
	IgnoreBots    bool
	OnTrigger     func(ReviewTrigger) error
	OnEvent       func(eventType, outcome string)
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

	eventType := r.Header.Get("X-Gitea-Event")
	if h.RequireSecret && h.Secret == "" {
		h.recordEvent(eventType, "rejected")
		http.Error(w, "webhook secret not configured", http.StatusUnauthorized)
		return
	}
	if h.Secret != "" {
		sig := r.Header.Get("X-Gitea-Signature")
		if !VerifySignature(h.Secret, body, sig) {
			h.recordEvent(eventType, "rejected")
			http.Error(w, "invalid signature", http.StatusUnauthorized)
			return
		}
	}

	trigger, ok, err := h.parseEvent(eventType, body)
	if err != nil {
		h.recordEvent(eventType, "rejected")
		http.Error(w, fmt.Sprintf("invalid payload: %v", err), http.StatusBadRequest)
		return
	}
	if !ok {
		h.recordEvent(eventType, "ignored")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ignored"))
		return
	}

	if h.OnTrigger != nil {
		if err := h.OnTrigger(trigger); err != nil {
			h.recordEvent(eventType, "error")
			http.Error(w, fmt.Sprintf("enqueue failed: %v", err), http.StatusInternalServerError)
			return
		}
	}

	h.recordEvent(eventType, "accepted")
	w.WriteHeader(http.StatusAccepted)
	_, _ = w.Write([]byte("accepted"))
}

func (h *WebhookHandler) recordEvent(eventType, outcome string) {
	if h.OnEvent != nil {
		h.OnEvent(eventType, outcome)
	}
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
		if h.SkipDrafts && IsDraftPR(ev.PullRequest) {
			return ReviewTrigger{}, false, nil
		}
		prAuthor := firstNonEmpty(ev.PullRequest.User.Username, ev.PullRequest.User.Login)
		sender := firstNonEmpty(ev.Sender.Username, ev.Sender.Login)
		if h.BotUsername != "" && (strings.EqualFold(prAuthor, h.BotUsername) || strings.EqualFold(sender, h.BotUsername)) {
			return ReviewTrigger{}, false, nil
		}
		if h.IgnoreBots && (IsBotUser(ev.PullRequest.User) || IsBotUser(ev.Sender)) {
			return ReviewTrigger{}, false, nil
		}
		owner, repo := splitFullName(ev.Repository.FullName)
		if owner == "" || repo == "" {
			return ReviewTrigger{}, false, errors.New("missing repository full_name")
		}
		return ReviewTrigger{
			Kind:     "pr_review",
			IsFork:   detectForkPR(ev.PullRequest, ev.Repository),
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
		// Ignore comments authored by the bot itself or other bots to prevent infinite loops.
		sender := firstNonEmpty(ev.Sender.Username, ev.Sender.Login, ev.Comment.User.Username, ev.Comment.User.Login)
		if h.BotUsername != "" && strings.EqualFold(sender, h.BotUsername) {
			return ReviewTrigger{}, false, nil
		}
		if h.IgnoreBots && (IsBotUser(ev.Sender) || IsBotUser(ev.Comment.User)) {
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
		kind, command, instruction := ParseBotCommand(ev.Comment.Body, h.BotUsername)
		return ReviewTrigger{
			Kind:        kind,
			Command:     command,
			Owner:       owner,
			Repo:        repo,
			CloneURL:    ev.Repository.CloneURL,
			PRNumber:    ev.Issue.Number,
			PRTitle:     ev.Issue.Title,
			PRBody:      ev.Issue.Body,
			CommentID:   ev.Comment.ID,
			CommentBy:   sender,
			Instruction: instruction,
		}, true, nil

	case "pull_request_review_comment", "pull_request_review":
		var ev PullReviewCommentEvent
		if err := json.Unmarshal(payload, &ev); err != nil {
			return ReviewTrigger{}, false, err
		}
		if ev.Action != "" && ev.Action != "created" {
			return ReviewTrigger{}, false, nil
		}
		sender := firstNonEmpty(ev.Sender.Username, ev.Sender.Login, ev.Comment.User.Username, ev.Comment.User.Login)
		if h.BotUsername != "" && strings.EqualFold(sender, h.BotUsername) {
			return ReviewTrigger{}, false, nil
		}
		if h.IgnoreBots && (IsBotUser(ev.Sender) || IsBotUser(ev.Comment.User)) {
			return ReviewTrigger{}, false, nil
		}
		if h.BotUsername != "" && !strings.Contains(strings.ToLower(ev.Comment.Body), "@"+strings.ToLower(h.BotUsername)) {
			return ReviewTrigger{}, false, nil
		}
		owner, repo := splitFullName(ev.Repository.FullName)
		if owner == "" || repo == "" {
			return ReviewTrigger{}, false, errors.New("missing repository full_name")
		}
		kind, command, instruction := ParseBotCommand(ev.Comment.Body, h.BotUsername)
		reviewLine := ev.Comment.NewLine
		if reviewLine <= 0 {
			reviewLine = ev.Comment.Line
		}
		return ReviewTrigger{
			Kind:            kind,
			Command:         command,
			IsFork:          detectForkPR(ev.PullRequest, ev.Repository),
			Owner:           owner,
			Repo:            repo,
			CloneURL:        ev.Repository.CloneURL,
			PRNumber:        ev.PullRequest.Number,
			PRTitle:         ev.PullRequest.Title,
			PRBody:          ev.PullRequest.Body,
			BaseRef:         ev.PullRequest.Base.Ref,
			HeadRef:         ev.PullRequest.Head.Ref,
			HeadSHA:         ev.PullRequest.Head.SHA,
			CommentID:       ev.Comment.ID,
			CommentIsReview: true,
			CommentBy:       sender,
			Instruction:     instruction,
			ReviewPath:      ev.Comment.Path,
			ReviewLine:      reviewLine,
			ReviewDiffHunk:  ev.Comment.DiffHunk,
		}, true, nil

	default:
		return ReviewTrigger{}, false, nil
	}
}

func isReviewablePRAction(action string) bool {
	switch action {
	case "opened", "reopened", "synchronized", "synchronize", "ready_for_review":
		return true
	default:
		return false
	}
}

// ParseBotCommand extracts slash commands following @botUsername in a PR comment.
func ParseBotCommand(body, botUsername string) (kind, command, instruction string) {
	trimmed := strings.TrimSpace(body)
	after := trimmed
	if botUsername != "" {
		mention := "@" + strings.ToLower(botUsername)
		lower := strings.ToLower(trimmed)
		if idx := strings.Index(lower, mention); idx != -1 {
			after = strings.TrimSpace(trimmed[idx+len(mention):])
		}
	}
	fields := strings.Fields(after)
	if len(fields) == 0 {
		return "comment_reply", "ask", trimmed
	}
	cmdToken := strings.ToLower(fields[0])
	rest := strings.TrimSpace(strings.TrimPrefix(after, fields[0]))
	switch cmdToken {
	case "/review", "review":
		return "pr_review", "force_review", rest
	case "/summary", "summary", "/describe", "describe":
		return "comment_reply", "summary", rest
	case "/fix", "fix":
		return "comment_reply", "fix", rest
	case "/ci", "ci":
		return "comment_reply", "ci", rest
	case "/redteam", "redteam":
		return "pr_review", "redteam", rest
	// State-changing commands require the explicit slash form so a question that merely
	// starts with the word "resume" or "resolve" cannot trigger them.
	case "/pause":
		return "comment_reply", "pause", ""
	case "/resume":
		return "comment_reply", "resume", ""
	case "/resolve":
		return "comment_reply", "resolve", ""
	case "/help", "help":
		return "comment_reply", "help", ""
	default:
		return "comment_reply", "ask", trimmed
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

// IsDraftPR reports whether pr is marked as draft or has a WIP title prefix.
func IsDraftPR(pr PullRequest) bool {
	if pr.Draft {
		return true
	}
	upper := strings.ToUpper(strings.TrimSpace(pr.Title))
	return strings.HasPrefix(upper, "WIP:") || strings.HasPrefix(upper, "[WIP]")
}

// IsBotUser reports whether u represents a bot account.
func IsBotUser(u User) bool {
	if strings.EqualFold(strings.TrimSpace(u.Type), "Bot") {
		return true
	}
	name := strings.ToLower(strings.TrimSpace(firstNonEmpty(u.Username, u.Login)))
	return strings.HasSuffix(name, "[bot]")
}

// IsForkPR reports whether pr originates from a different repository than baseRepo.
func IsForkPR(pr PullRequest, baseRepo Repository) bool {
	return detectForkPR(pr, baseRepo)
}

func detectForkPR(pr PullRequest, baseRepo Repository) bool {
	if pr.Head.Repo.ID != 0 && pr.Base.Repo.ID != 0 && pr.Head.Repo.ID != pr.Base.Repo.ID {
		return true
	}
	if pr.Head.Repo.ID != 0 && baseRepo.ID != 0 && pr.Head.Repo.ID != baseRepo.ID {
		return true
	}
	if pr.Head.Repo.FullName != "" && baseRepo.FullName != "" &&
		!strings.EqualFold(pr.Head.Repo.FullName, baseRepo.FullName) {
		return true
	}
	return false
}
