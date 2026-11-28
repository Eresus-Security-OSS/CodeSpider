package worker

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Eresus-Security-OSS/CodeSpider/internal/gitea"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/provider"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/store"
)

const (
	maxResolvePerCommand   = 200
	maxResolveEarlyFailure = 3
)

// isControlCommand reports whether cmd only changes per-PR bot state or review threads,
// so it can run without cloning the repository or calling the LLM.
func isControlCommand(cmd string) bool {
	switch cmd {
	case "pause", "resume", "resolve":
		return true
	default:
		return false
	}
}

func (p *Pool) botName() string {
	if p.authorName != "" {
		return p.authorName
	}
	return "codespider"
}

// runControlCommand executes /pause, /resume, or /resolve. All three require the commenter
// to be a repository collaborator because they change what the bot does on the PR.
func (p *Pool) runControlCommand(ctx context.Context, t gitea.ReviewTrigger, prKey string, startedAt time.Time, out *DryRunResult) error {
	out.Verdict = "COMMENT"
	if t.DryRun {
		out.Summary = fmt.Sprintf("dry-run: `/%s` would run on %s without side effects", t.Command, prKey)
		return nil
	}
	if p.forge == nil || p.store == nil {
		return errors.New("control commands require a forge client and state store")
	}
	if t.Command == "resolve" {
		if _, ok := p.forge.(provider.ReviewThreadResolver); !ok {
			return p.refuseControl(ctx, t, startedAt, "review thread resolution is not supported by the configured forge")
		}
	}
	if t.CommentID > 0 {
		_ = p.addCommentReaction(ctx, t, "eyes")
	}

	if t.CommentBy == "" {
		return p.refuseControl(ctx, t, startedAt, "the commenter could not be identified")
	}
	ok, err := p.forge.IsCollaborator(ctx, t.Owner, t.Repo, t.CommentBy)
	if err != nil || !ok {
		return p.refuseControl(ctx, t, startedAt, fmt.Sprintf("`@%s` is not a repository collaborator", t.CommentBy))
	}

	var msg string
	switch t.Command {
	case "pause":
		msg, err = p.pausePR(prKey)
	case "resume":
		msg, err = p.resumePR(t, prKey)
	case "resolve":
		msg, err = p.resolveBotThreads(ctx, t)
	}
	if err != nil {
		p.finishWithError(prKey, t, startedAt, 0, 0, 0, err)
		return err
	}

	out.Summary = msg
	if err := p.forge.PostComment(ctx, t.Owner, t.Repo, t.PRNumber, msg); err != nil {
		p.finishWithError(prKey, t, startedAt, 0, 0, 0, err)
		return err
	}
	dur := time.Since(startedAt)
	p.metrics.RecordRun(t.Kind, "success", 0, 0, 0, dur)
	_ = p.store.RecordRun(store.RunRecord{
		PRKey:      prKey,
		Kind:       t.Kind,
		HeadSHA:    t.HeadSHA,
		DurationMs: dur.Milliseconds(),
		Status:     "success",
		FinishedAt: time.Now().UTC(),
	})
	return nil
}

func (p *Pool) refuseControl(ctx context.Context, t gitea.ReviewTrigger, startedAt time.Time, reason string) error {
	msg := fmt.Sprintf("Refusing `/%s`: %s.", t.Command, reason)
	_ = p.forge.PostComment(ctx, t.Owner, t.Repo, t.PRNumber, msg)
	p.metrics.RecordRun(t.Kind, "skipped", 0, 0, 0, time.Since(startedAt))
	return fmt.Errorf("unauthorized /%s command", t.Command)
}

func (p *Pool) pausePR(prKey string) (string, error) {
	changed, err := p.store.SetPaused(prKey, true)
	if err != nil {
		return "", err
	}
	if !changed {
		return "Automatic reviews are already paused for this PR.", nil
	}
	return fmt.Sprintf("Automatic reviews are paused for this PR. `@%s /review` still runs a review on demand; use `@%s /resume` to turn automatic reviews back on.", p.botName(), p.botName()), nil
}

func (p *Pool) resumePR(t gitea.ReviewTrigger, prKey string) (string, error) {
	changed, err := p.store.SetPaused(prKey, false)
	if err != nil {
		return "", err
	}
	if !changed {
		return "Automatic reviews were not paused for this PR.", nil
	}
	// The trigger has no head SHA, so runJob hydrates it and skips the run if that commit was already reviewed.
	if err := p.Enqueue(gitea.ReviewTrigger{Kind: "pr_review", Owner: t.Owner, Repo: t.Repo, CloneURL: t.CloneURL, PRNumber: t.PRNumber}); err != nil {
		return "Automatic reviews resumed. The review queue is full, so the current commit will be picked up by the next reconcile pass.", nil
	}
	return "Automatic reviews resumed. Reviewing the current commit now.", nil
}

func isUserNamed(u gitea.User, name string) bool {
	login := u.Username
	if login == "" {
		login = u.Login
	}
	return login != "" && strings.EqualFold(login, name)
}

// resolveBotThreads resolves every unresolved inline review comment authored by the bot on the PR.
func (p *Pool) resolveBotThreads(ctx context.Context, t gitea.ReviewTrigger) (string, error) {
	resolver, ok := p.forge.(provider.ReviewThreadResolver)
	if !ok {
		return "", errors.New("the configured forge does not support resolving review threads")
	}
	bot := p.botName()
	reviews, err := p.forge.ListPullReviews(ctx, t.Owner, t.Repo, t.PRNumber)
	if err != nil {
		return "", fmt.Errorf("list reviews: %w", err)
	}

	var resolved, failed int
	var lastErr error
	truncated := false
scan:
	for _, rv := range reviews {
		if !isUserNamed(rv.User, bot) {
			continue
		}
		comments, err := resolver.ListPullReviewComments(ctx, t.Owner, t.Repo, t.PRNumber, rv.ID)
		if err != nil {
			failed++
			lastErr = err
			continue
		}
		for _, c := range comments {
			if c.Resolved() || !isUserNamed(c.User, bot) {
				continue
			}
			if resolved+failed >= maxResolvePerCommand {
				truncated = true
				break scan
			}
			if err := resolver.ResolveReviewComment(ctx, t.Owner, t.Repo, c.ID); err != nil {
				failed++
				lastErr = err
				if resolved == 0 && failed >= maxResolveEarlyFailure {
					break scan
				}
				continue
			}
			resolved++
		}
	}

	var b strings.Builder
	switch {
	case resolved == 0 && failed == 0:
		b.WriteString("No open CodeSpider review threads to resolve on this PR.")
	default:
		fmt.Fprintf(&b, "Resolved %d CodeSpider review thread(s).", resolved)
	}
	if truncated {
		fmt.Fprintf(&b, " Stopped after %d threads; run `/resolve` again for the rest.", maxResolvePerCommand)
	}
	if failed > 0 {
		detail := sanitizeTableCell(lastErr.Error())
		if len(detail) > 200 {
			detail = detail[:200]
		}
		fmt.Fprintf(&b, "\n\n%d thread(s) could not be resolved. The server may not support the resolve API, or the bot lacks permission. Last error: `%s`", failed, detail)
	}
	return b.String(), nil
}
