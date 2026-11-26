// Package worker manages the 24/7 asynchronous review queue, PR superseding, and execution.
package worker

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/Eresus-Security-OSS/CodeSpider/internal/agent"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/gitea"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/repoconfig"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/store"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/tools"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/workspace"
)

// Pool processes Gitea triggers concurrently with per-PR superseding.
type Pool struct {
	workers     int
	enableWrite bool
	authorName  string
	queue       chan gitea.ReviewTrigger
	gitea       *gitea.Client
	workspace   *workspace.Manager
	agent       *agent.Runner
	store       *store.Store
	logger      *slog.Logger

	mu     sync.Mutex
	active map[string]context.CancelFunc
	wg     sync.WaitGroup
}

// Config bundles dependencies for the worker Pool.
type Config struct {
	Workers     int
	QueueSize   int
	EnableWrite bool
	AuthorName  string
	Gitea       *gitea.Client
	Workspace   *workspace.Manager
	Agent       *agent.Runner
	Store       *store.Store
	Logger      *slog.Logger
}

// NewPool creates a new worker Pool.
func NewPool(cfg Config) *Pool {
	if cfg.Workers < 1 {
		cfg.Workers = 2
	}
	if cfg.QueueSize < 1 {
		cfg.QueueSize = 128
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Pool{
		workers:     cfg.Workers,
		enableWrite: cfg.EnableWrite,
		authorName:  cfg.AuthorName,
		queue:       make(chan gitea.ReviewTrigger, cfg.QueueSize),
		gitea:       cfg.Gitea,
		workspace:   cfg.Workspace,
		agent:       cfg.Agent,
		store:       cfg.Store,
		logger:      cfg.Logger,
		active:      make(map[string]context.CancelFunc),
	}
}

// Start launches the worker goroutines until ctx is canceled.
func (p *Pool) Start(ctx context.Context) {
	for i := 0; i < p.workers; i++ {
		p.wg.Add(1)
		go p.runWorker(ctx, i+1)
	}
}

// Wait blocks until all worker goroutines exit.
func (p *Pool) Wait() {
	p.wg.Wait()
}

// Enqueue submits a trigger to the worker queue without blocking indefinitely.
func (p *Pool) Enqueue(t gitea.ReviewTrigger) error {
	select {
	case p.queue <- t:
		return nil
	default:
		return errors.New("worker queue is full")
	}
}

// ActiveCount returns the number of PR jobs currently executing.
func (p *Pool) ActiveCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.active)
}

func (p *Pool) runWorker(ctx context.Context, id int) {
	defer p.wg.Done()
	p.logger.Info("worker started", "worker_id", id)
	for {
		select {
		case <-ctx.Done():
			p.logger.Info("worker stopping", "worker_id", id)
			return
		case trigger := <-p.queue:
			p.handleTrigger(ctx, id, trigger)
		}
	}
}

func (p *Pool) handleTrigger(parentCtx context.Context, workerID int, t gitea.ReviewTrigger) {
	prKey := store.PRKey(t.Owner, t.Repo, t.PRNumber)

	// Hydrate PR metadata if missing (e.g. from an issue_comment webhook).
	if t.HeadSHA == "" || t.CloneURL == "" {
		pr, err := p.gitea.GetPullRequest(parentCtx, t.Owner, t.Repo, t.PRNumber)
		if err != nil {
			p.logger.Error("failed to hydrate PR", "pr", prKey, "err", err)
			return
		}
		if t.HeadSHA == "" {
			t.HeadSHA = pr.Head.SHA
		}
		if t.BaseRef == "" {
			t.BaseRef = pr.Base.Ref
		}
		if t.HeadRef == "" {
			t.HeadRef = pr.Head.Ref
		}
		if t.CloneURL == "" {
			t.CloneURL = pr.Base.Repo.CloneURL
		}
	}

	if t.Kind == "pr_review" && p.store.IsAlreadyReviewed(prKey, t.HeadSHA) {
		p.logger.Info("skipping already reviewed commit", "pr", prKey, "sha", t.HeadSHA)
		return
	}

	// Cancel any in-flight run for the same PR so newer commits supersede older ones.
	jobCtx, cancel := context.WithTimeout(parentCtx, 5*time.Minute)
	p.registerActive(prKey, cancel)
	defer func() {
		cancel()
		p.clearActive(prKey)
	}()

	p.logger.Info("starting agent run", "worker_id", workerID, "pr", prKey, "kind", t.Kind, "sha", t.HeadSHA)
	if t.Kind == "pr_review" {
		_ = p.gitea.SetCommitStatus(jobCtx, t.Owner, t.Repo, t.HeadSHA, "pending", "CodeSpider review in progress")
	}

	diff, err := p.gitea.GetPullRequestDiff(jobCtx, t.Owner, t.Repo, t.PRNumber)
	if err != nil {
		p.finishWithError(prKey, t, 0, 0, 0, fmt.Errorf("fetch diff: %w", err))
		return
	}

	wtDir, cleanup, err := p.workspace.CheckoutPR(jobCtx, t.Owner, t.Repo, t.CloneURL, t.HeadSHA)
	if err != nil {
		p.logger.Warn("worktree checkout failed, continuing with diff-only tools", "pr", prKey, "err", err)
	} else {
		defer cleanup()
	}

	repoCfg := repoconfig.Load(wtDir)
	if t.Kind == "pr_review" && !repoCfg.Enabled {
		p.logger.Info("skipping PR review per .codespider.yaml", "pr", prKey)
		_ = p.gitea.SetCommitStatus(jobCtx, t.Owner, t.Repo, t.HeadSHA, "success", "CodeSpider skipped by repository config")
		return
	}
	if len(repoCfg.IgnorePaths) > 0 {
		var skipped []string
		diff, skipped = repoconfig.FilterDiff(diff, repoCfg.IgnorePaths)
		if len(skipped) > 0 {
			p.logger.Info("filtered ignored paths from diff", "pr", prKey, "skipped_count", len(skipped))
		}
		if t.Kind == "pr_review" && diff == "" {
			p.logger.Info("skipping PR review; all changed files matched ignore_paths", "pr", prKey)
			_ = p.gitea.SetCommitStatus(jobCtx, t.Owner, t.Repo, t.HeadSHA, "success", "CodeSpider skipped (only ignored paths changed)")
			return
		}
	}
	t.RepoInstructions = repoCfg.Instructions

	reg := tools.NewRegistry(tools.Params{
		WorktreeDir: wtDir,
		Workspace:   p.workspace,
		Gitea:       p.gitea,
		Trigger:     t,
		Diff:        diff,
		EnableWrite: p.enableWrite,
		AuthorName:  p.authorName,
	})

	res, err := p.agent.Run(jobCtx, t, reg)
	if err != nil {
		p.finishWithError(prKey, t, res.StepsUsed, res.TokensUsed, res.InlineComments, err)
		return
	}

	// Fallback: if the agent returned text without calling submit_review/reply_comment, post it.
	if !res.Submitted && res.FinalText != "" {
		if postErr := p.gitea.PostComment(jobCtx, t.Owner, t.Repo, t.PRNumber, res.FinalText); postErr != nil {
			p.finishWithError(prKey, t, res.StepsUsed, res.TokensUsed, res.InlineComments, postErr)
			return
		}
	}

	if t.Kind == "pr_review" {
		_ = p.gitea.SetCommitStatus(jobCtx, t.Owner, t.Repo, t.HeadSHA, "success",
			fmt.Sprintf("CodeSpider completed (%d inline comments)", res.InlineComments))
	}

	_ = p.store.RecordRun(store.RunRecord{
		PRKey:          prKey,
		Kind:           t.Kind,
		HeadSHA:        t.HeadSHA,
		StepsUsed:      res.StepsUsed,
		TokensUsed:     res.TokensUsed,
		InlineComments: res.InlineComments,
		Status:         "success",
		FinishedAt:     time.Now().UTC(),
	})

	p.logger.Info("completed agent run",
		"pr", prKey,
		"steps", res.StepsUsed,
		"tokens", res.TokensUsed,
		"inline_comments", res.InlineComments,
	)
}

func (p *Pool) finishWithError(prKey string, t gitea.ReviewTrigger, steps, tokens, comments int, err error) {
	status := "failed"
	if errors.Is(err, context.Canceled) {
		status = "canceled"
	} else if t.Kind == "pr_review" {
		_ = p.gitea.SetCommitStatus(context.Background(), t.Owner, t.Repo, t.HeadSHA, "error", "CodeSpider review failed")
	}

	p.logger.Error("agent run failed", "pr", prKey, "status", status, "err", err)
	_ = p.store.RecordRun(store.RunRecord{
		PRKey:          prKey,
		Kind:           t.Kind,
		HeadSHA:        t.HeadSHA,
		StepsUsed:      steps,
		TokensUsed:     tokens,
		InlineComments: comments,
		Status:         status,
		Error:          err.Error(),
		FinishedAt:     time.Now().UTC(),
	})
}

func (p *Pool) registerActive(prKey string, cancel context.CancelFunc) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if prev, ok := p.active[prKey]; ok {
		prev()
	}
	p.active[prKey] = cancel
}

func (p *Pool) clearActive(prKey string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.active, prKey)
}
