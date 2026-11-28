// Package worker manages the 24/7 asynchronous review queue, PR superseding, and execution.
package worker

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/Eresus-Security-OSS/CodeSpider/internal/agent"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/analysis"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/audit"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/events"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/evidence"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/gitea"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/memory"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/metrics"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/opsintel"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/orggraph"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/policy"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/repoconfig"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/sandbox"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/security"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/store"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/tools"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/workspace"
)

type activeJob struct {
	id     uint64
	cancel context.CancelFunc
}

// DryRunResult captures the full output of a synchronous, offline, or dry-run PR review.
type DryRunResult struct {
	PRKey           string                `json:"pr_key"`
	Model           string                `json:"model"`
	Verdict         string                `json:"verdict"`
	Summary         string                `json:"summary"`
	InlineComments  []gitea.ReviewComment `json:"inline_comments"`
	Findings        []evidence.Finding    `json:"findings,omitempty"`
	SecretFindings  []security.Finding    `json:"secret_findings,omitempty"`
	Stages          []StageMetric         `json:"stages,omitempty"`
	StepsUsed       int                   `json:"steps_used"`
	TokensUsed      int                   `json:"tokens_used"`
	BlueTeamRefuted int                   `json:"blue_team_refuted"`
	SuppressedCount int                   `json:"suppressed_count,omitempty"`
	DurationMs      int64                 `json:"duration_ms"`
}

// Pool processes Gitea triggers concurrently with per-PR superseding.
type Pool struct {
	workers                 int
	enableWrite             bool
	enableProofOfBug        bool
	authorName              string
	skipDrafts              bool
	ignoreBots              bool
	stickySummary           bool
	requireCollabFix        bool
	allowSameOwnerCrossRepo bool
	crossRepoAllowlist      []string
	sandboxMode             string
	alertWebhookURL         string
	jobTimeout              time.Duration
	queue                   chan gitea.ReviewTrigger
	gitea                   *gitea.Client
	workspace               *workspace.Manager
	agent                   *agent.Runner
	store                   *store.Store
	metrics                 *metrics.Collector
	events                  *events.Broker
	audit                   *audit.Logger
	sandbox                 *sandbox.Executor
	analysis                *analysis.Pipeline
	memory                  *memory.Store
	orgGraph                *orggraph.Graph
	opsIntel                *opsintel.Correlator
	logger                  *slog.Logger

	mu        sync.Mutex
	nextJobID uint64
	active    map[string]activeJob
	wg        sync.WaitGroup
}

// Config bundles dependencies for the worker Pool.
type Config struct {
	Workers   int
	QueueSize int
	// JobTimeout bounds one PR review job end to end. Zero means 5 minutes.
	JobTimeout                time.Duration
	EnableWrite               bool
	EnableProofOfBug          bool
	AuthorName                string
	SkipDrafts                bool
	IgnoreBots                bool
	StickySummary             bool
	RequireCollaboratorForFix bool
	AllowSameOwnerCrossRepo   bool
	CrossRepoAllowlist        []string
	SandboxMode               string
	AlertWebhookURL           string
	Gitea                     *gitea.Client
	Workspace                 *workspace.Manager
	Agent                     *agent.Runner
	Store                     *store.Store
	Metrics                   *metrics.Collector
	Events                    *events.Broker
	Audit                     *audit.Logger
	Sandbox                   *sandbox.Executor
	Analysis                  *analysis.Pipeline
	Memory                    *memory.Store
	OrgGraph                  *orggraph.Graph
	OpsIntel                  *opsintel.Correlator
	Logger                    *slog.Logger
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
	if cfg.Analysis == nil {
		cfg.Analysis = analysis.NewPipeline()
	}
	if cfg.Sandbox == nil {
		cfg.Sandbox = sandbox.NewExecutor(sandbox.Config{Mode: cfg.SandboxMode})
	}
	return &Pool{
		workers:                 cfg.Workers,
		enableWrite:             cfg.EnableWrite,
		enableProofOfBug:        cfg.EnableProofOfBug,
		authorName:              cfg.AuthorName,
		skipDrafts:              cfg.SkipDrafts,
		ignoreBots:              cfg.IgnoreBots,
		stickySummary:           cfg.StickySummary,
		requireCollabFix:        cfg.RequireCollaboratorForFix,
		allowSameOwnerCrossRepo: cfg.AllowSameOwnerCrossRepo,
		crossRepoAllowlist:      append([]string(nil), cfg.CrossRepoAllowlist...),
		sandboxMode:             cfg.SandboxMode,
		alertWebhookURL:         cfg.AlertWebhookURL,
		jobTimeout:              jobTimeoutOrDefault(cfg.JobTimeout),
		queue:                   make(chan gitea.ReviewTrigger, cfg.QueueSize),
		gitea:                   cfg.Gitea,
		workspace:               cfg.Workspace,
		agent:                   cfg.Agent,
		store:                   cfg.Store,
		metrics:                 cfg.Metrics,
		events:                  cfg.Events,
		audit:                   cfg.Audit,
		sandbox:                 cfg.Sandbox,
		analysis:                cfg.Analysis,
		memory:                  cfg.Memory,
		orgGraph:                cfg.OrgGraph,
		opsIntel:                cfg.OpsIntel,
		logger:                  cfg.Logger,
		active:                  make(map[string]activeJob),
	}
}

// UpdateRuntimeConfig updates hot-reloadable pool settings safely on SIGHUP.
func (p *Pool) UpdateRuntimeConfig(stickySummary bool, alertWebhookURL string, allowSameOwner bool, allowlist []string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.stickySummary = stickySummary
	p.alertWebhookURL = alertWebhookURL
	p.allowSameOwnerCrossRepo = allowSameOwner
	p.crossRepoAllowlist = append([]string(nil), allowlist...)
}

// Start launches the worker goroutines until ctx is canceled.
func (p *Pool) Start(ctx context.Context) {
	for i := 0; i < p.workers; i++ {
		p.wg.Add(1)
		go p.runWorker(ctx, i+1)
	}
}

// StartReconciler periodically scans open pull requests to recover missed webhooks.
func (p *Pool) StartReconciler(ctx context.Context, interval time.Duration, repos []string) {
	if interval <= 0 || p.gitea == nil {
		return
	}
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		p.logger.Info("reconciler started", "interval", interval.String(), "configured_repos", len(repos))

		initialTimer := time.NewTimer(10 * time.Second)
		select {
		case <-ctx.Done():
			initialTimer.Stop()
			return
		case <-initialTimer.C:
			p.ReconcileOnce(ctx, repos)
		}

		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				p.logger.Info("reconciler stopping")
				return
			case <-ticker.C:
				p.ReconcileOnce(ctx, repos)
			}
		}
	}()
}

// ReconcileOnce checks open PRs across configured or accessible repositories and enqueues unreviewed ones.
func (p *Pool) ReconcileOnce(ctx context.Context, repos []string) int {
	if p.gitea == nil || ctx.Err() != nil {
		return 0
	}
	targets, err := p.resolveReconcileTargets(ctx, repos)
	if err != nil {
		p.logger.Warn("reconciler failed to list repositories", "err", err)
		p.metrics.RecordReconcile(false)
		return 0
	}

	enqueued := 0
	hadError := false
	for _, target := range targets {
		if ctx.Err() != nil {
			break
		}
		prs, err := p.gitea.ListOpenPullRequests(ctx, target.owner, target.repo)
		if err != nil {
			hadError = true
			p.logger.Warn("reconciler failed to list open PRs", "repo", target.owner+"/"+target.repo, "err", err)
			continue
		}
		for _, pr := range prs {
			if p.skipDrafts && gitea.IsDraftPR(pr) {
				continue
			}
			prAuthor := pr.User.Username
			if prAuthor == "" {
				prAuthor = pr.User.Login
			}
			if p.authorName != "" && strings.EqualFold(prAuthor, p.authorName) {
				continue
			}
			if p.ignoreBots && gitea.IsBotUser(pr.User) {
				continue
			}
			prKey := store.PRKey(target.owner, target.repo, pr.Number)
			if p.IsActive(prKey) || p.store.IsPaused(prKey) || p.store.IsAlreadyReviewed(prKey, pr.Head.SHA) {
				continue
			}
			cloneURL := pr.Base.Repo.CloneURL
			if cloneURL == "" {
				cloneURL = target.cloneURL
			}
			err := p.Enqueue(gitea.ReviewTrigger{
				Kind:     "pr_review",
				IsFork:   gitea.IsForkPR(pr, pr.Base.Repo),
				Owner:    target.owner,
				Repo:     target.repo,
				CloneURL: cloneURL,
				PRNumber: pr.Number,
				PRTitle:  pr.Title,
				PRBody:   pr.Body,
				BaseRef:  pr.Base.Ref,
				HeadRef:  pr.Head.Ref,
				HeadSHA:  pr.Head.SHA,
			})
			if err != nil {
				p.logger.Warn("reconciler failed to enqueue PR", "pr", prKey, "err", err)
				break
			}
			enqueued++
		}
	}
	p.metrics.RecordReconcile(!hadError)
	if enqueued > 0 {
		p.logger.Info("reconciler enqueued unreviewed PRs", "count", enqueued)
	}
	return enqueued
}

type repoTarget struct {
	owner    string
	repo     string
	cloneURL string
}

func (p *Pool) resolveReconcileTargets(ctx context.Context, repos []string) ([]repoTarget, error) {
	if len(repos) > 0 {
		out := make([]repoTarget, 0, len(repos))
		for _, slug := range repos {
			owner, repo, ok := strings.Cut(strings.TrimSpace(slug), "/")
			if ok && owner != "" && repo != "" {
				out = append(out, repoTarget{owner: owner, repo: repo})
			}
		}
		return out, nil
	}
	accessible, err := p.gitea.ListAccessibleRepos(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]repoTarget, 0, len(accessible))
	for _, r := range accessible {
		owner, repo, ok := strings.Cut(strings.TrimSpace(r.FullName), "/")
		if ok && owner != "" && repo != "" {
			out = append(out, repoTarget{owner: owner, repo: repo, cloneURL: r.CloneURL})
		}
	}
	return out, nil
}

// Wait blocks until all worker and reconciler goroutines exit.
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

// IsActive reports whether a job is currently executing for prKey.
func (p *Pool) IsActive(prKey string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	_, ok := p.active[prKey]
	return ok
}

// QueueDepth returns the number of triggers currently waiting in the queue.
func (p *Pool) QueueDepth() int {
	return len(p.queue)
}

// ExecuteSync runs a single review or dry-run synchronously and returns the full result.
func (p *Pool) ExecuteSync(ctx context.Context, t gitea.ReviewTrigger) (DryRunResult, error) {
	if t.Kind == "" {
		t.Kind = "pr_review"
	}
	return p.runJob(ctx, 0, t)
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
	_, _ = p.runJob(parentCtx, workerID, t)
}

func (p *Pool) runJob(parentCtx context.Context, workerID int, t gitea.ReviewTrigger) (DryRunResult, error) {
	startedAt := time.Now()
	prKey := store.PRKey(t.Owner, t.Repo, t.PRNumber)
	out := DryRunResult{PRKey: prKey}

	// Fast-path for /help command without cloning or calling the LLM.
	if t.Command == "help" {
		if !t.DryRun && t.CommentID > 0 && p.gitea != nil {
			_ = p.gitea.AddCommentReaction(parentCtx, t.Owner, t.Repo, t.CommentID, "eyes")
		}
		helpText := p.buildHelpMessage()
		out.Summary = helpText
		out.Verdict = "COMMENT"
		if !t.DryRun && p.gitea != nil {
			if err := p.gitea.PostComment(parentCtx, t.Owner, t.Repo, t.PRNumber, helpText); err != nil {
				p.finishWithError(prKey, t, startedAt, 0, 0, 0, err)
				return out, err
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
		}
		return out, nil
	}

	// Control commands mutate per-PR bot state and never clone or call the LLM.
	if isControlCommand(t.Command) {
		return out, p.runControlCommand(parentCtx, t, prKey, startedAt, &out)
	}

	// /pause suppresses automatic reviews; explicit /review and /redteam still run.
	if !t.DryRun && t.Kind == "pr_review" && t.Command == "" && p.store != nil && p.store.IsPaused(prKey) {
		p.logger.Info("skipping automatic review: PR is paused", "pr", prKey)
		p.metrics.RecordRun(t.Kind, "skipped", 0, 0, 0, time.Since(startedAt))
		return out, nil
	}

	// Collaborator authorization gate for /fix commands.
	if !t.DryRun && t.Command == "fix" && p.requireCollabFix && t.CommentBy != "" && p.gitea != nil {
		ok, err := p.gitea.IsCollaborator(parentCtx, t.Owner, t.Repo, t.CommentBy)
		if err != nil || !ok {
			msg := fmt.Sprintf("Refusing `/fix` command: `@%s` is not a repository collaborator.", t.CommentBy)
			_ = p.gitea.PostComment(parentCtx, t.Owner, t.Repo, t.PRNumber, msg)
			p.metrics.RecordRun(t.Kind, "skipped", 0, 0, 0, time.Since(startedAt))
			return out, errors.New("unauthorized /fix command")
		}
	}

	// Hydrate PR metadata if missing (e.g. from an issue_comment webhook or CLI).
	var prAuthor string
	if t.HeadSHA == "" || t.CloneURL == "" || t.PRTitle == "" {
		if p.gitea != nil {
			pr, err := p.gitea.GetPullRequest(parentCtx, t.Owner, t.Repo, t.PRNumber)
			if err != nil {
				p.logger.Error("failed to hydrate PR", "pr", prKey, "err", err)
				return out, err
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
			if t.PRTitle == "" {
				t.PRTitle = pr.Title
			}
			if t.PRBody == "" {
				t.PRBody = pr.Body
			}
			if gitea.IsForkPR(pr, pr.Base.Repo) {
				t.IsFork = true
			}
			prAuthor = pr.User.Username
			if prAuthor == "" {
				prAuthor = pr.User.Login
			}
		}
	}

	isCollaborator := false
	if !t.IsFork && t.CommentBy != "" && p.gitea != nil {
		if ok, err := p.gitea.IsCollaborator(parentCtx, t.Owner, t.Repo, t.CommentBy); err == nil {
			isCollaborator = ok
		}
	}

	p.mu.Lock()
	allowSameOwner := p.allowSameOwnerCrossRepo
	crossAllowlist := append([]string(nil), p.crossRepoAllowlist...)
	sandboxMode := p.sandboxMode
	p.mu.Unlock()

	perms := policy.EvaluatePermissions(policy.Input{
		Owner:                   t.Owner,
		IsFork:                  t.IsFork,
		IsCollaborator:          isCollaborator,
		DryRun:                  t.DryRun,
		EnableWrite:             p.enableWrite,
		TriggerCommand:          t.Command,
		SandboxMode:             sandboxMode,
		AllowSameOwnerCrossRepo: allowSameOwner,
		AllowedCrossRepos:       crossAllowlist,
	})
	if !t.DryRun {
		p.audit.Log(audit.Event{
			Actor:    t.CommentBy,
			PRKey:    prKey,
			Action:   "run_start",
			Decision: "allow",
			Reason:   fmt.Sprintf("trust=%s is_fork=%v", perms.Trust, t.IsFork),
		})
	}

	if !t.DryRun && t.Kind == "pr_review" && t.Command != "force_review" && t.Command != "redteam" && p.store != nil && p.store.IsAlreadyReviewed(prKey, t.HeadSHA) {
		p.logger.Info("skipping already reviewed commit", "pr", prKey, "sha", t.HeadSHA)
		return out, nil
	}

	// Cancel any in-flight run for the same PR so newer commits supersede older ones.
	jobCtx, cancel := context.WithTimeout(parentCtx, p.jobTimeout)
	var jobID uint64
	if !t.DryRun {
		jobID = p.registerActive(prKey, cancel)
		defer func() {
			cancel()
			p.clearActive(prKey, jobID)
		}()
	} else {
		defer cancel()
	}

	p.logger.Info("starting agent run", "worker_id", workerID, "pr", prKey, "kind", t.Kind, "command", t.Command, "dry_run", t.DryRun, "sha", t.HeadSHA)

	if !t.DryRun && p.gitea != nil {
		if t.CommentID > 0 {
			_ = p.gitea.AddCommentReaction(jobCtx, t.Owner, t.Repo, t.CommentID, "eyes")
		} else if t.PRNumber > 0 {
			_ = p.gitea.AddIssueReaction(jobCtx, t.Owner, t.Repo, t.PRNumber, "eyes")
		}
		if t.Kind == "pr_review" {
			_ = p.gitea.SetCommitStatus(jobCtx, t.Owner, t.Repo, t.HeadSHA, "pending", "CodeSpider review in progress")
		}
	}

	diff, err := p.gitea.GetPullRequestDiff(jobCtx, t.Owner, t.Repo, t.PRNumber)
	if err != nil {
		if !t.DryRun {
			p.finishWithError(prKey, t, startedAt, 0, 0, 0, fmt.Errorf("fetch diff: %w", err))
		}
		return out, fmt.Errorf("fetch diff: %w", err)
	}

	var wtDir string
	if p.workspace != nil && t.CloneURL != "" {
		var cleanup func()
		if t.DryRun {
			wtDir, cleanup, err = p.workspace.CheckoutPRReadOnly(jobCtx, t.Owner, t.Repo, t.CloneURL, t.HeadSHA)
		} else {
			wtDir, cleanup, err = p.workspace.CheckoutPR(jobCtx, t.Owner, t.Repo, t.CloneURL, t.HeadSHA)
		}
		if err != nil {
			p.logger.Warn("worktree checkout failed, continuing with diff-only tools", "pr", prKey, "err", err)
		} else {
			defer cleanup()
		}
	}

	// Load trusted policy (.codespider.yaml) from the repository's base branch when available
	// so untrusted PR heads cannot disable review gates or ignore_paths.
	var trustedBaseYAML []byte
	if p.workspace != nil && t.BaseRef != "" {
		for _, cfgName := range []string{".codespider.yaml", ".codespider.yml"} {
			if raw, rErr := p.workspace.ReadMirrorFile(jobCtx, t.Owner, t.Repo, t.BaseRef, cfgName); rErr == nil && len(raw) > 0 {
				trustedBaseYAML = raw
				break
			}
		}
	}
	var repoCfg repoconfig.Config
	if t.IsFork {
		// Untrusted fork PRs contribute no settings or prompt instructions: policy, AGENTS.md-style
		// instruction files, and path_instructions all come from the base branch.
		repoCfg = repoconfig.LoadFromBase(trustedBaseYAML, p.baseFileReader(jobCtx, t))
	} else {
		repoCfg = repoconfig.LoadWithTrustedBase(wtDir, trustedBaseYAML)
	}
	if !t.DryRun && t.Kind == "pr_review" && t.Command != "force_review" && t.Command != "redteam" && !repoCfg.Enabled {
		p.logger.Info("skipping PR review per .codespider.yaml", "pr", prKey)
		if p.gitea != nil {
			_ = p.gitea.SetCommitStatus(jobCtx, t.Owner, t.Repo, t.HeadSHA, "success", "CodeSpider skipped by repository config")
		}
		p.metrics.RecordRun(t.Kind, "skipped", 0, 0, 0, time.Since(startedAt))
		return out, nil
	}
	if !t.DryRun && t.Kind == "pr_review" && t.Command != "force_review" && t.Command != "redteam" {
		if reason := repoCfg.SkipReason(t.BaseRef, t.PRTitle); reason != "" {
			p.logger.Info("skipping automatic PR review per .codespider.yaml", "pr", prKey, "reason", reason)
			if p.gitea != nil {
				_ = p.gitea.SetCommitStatus(jobCtx, t.Owner, t.Repo, t.HeadSHA, "success", "CodeSpider skipped: "+reason)
			}
			p.metrics.RecordRun(t.Kind, "skipped", 0, 0, 0, time.Since(startedAt))
			return out, nil
		}
	}
	if len(repoCfg.IgnorePaths) > 0 {
		var skipped []string
		diff, skipped = repoconfig.FilterDiff(diff, repoCfg.IgnorePaths)
		if len(skipped) > 0 {
			p.logger.Info("filtered ignored paths from diff", "pr", prKey, "skipped_count", len(skipped))
		}
		if !t.DryRun && t.Kind == "pr_review" && strings.TrimSpace(diff) == "" {
			p.logger.Info("skipping PR review; all changed files matched ignore_paths", "pr", prKey)
			if p.gitea != nil {
				_ = p.gitea.SetCommitStatus(jobCtx, t.Owner, t.Repo, t.HeadSHA, "success", "CodeSpider skipped (only ignored paths changed)")
			}
			p.metrics.RecordRun(t.Kind, "skipped", 0, 0, 0, time.Since(startedAt))
			return out, nil
		}
	}

	t.DiffLineCount = countDiffLines(diff)

	var incDiff string
	if p.store != nil && p.workspace != nil && wtDir != "" {
		prevSHA := p.store.LastReviewedSHA(prKey)
		if t.Kind == "pr_review" && prevSHA != "" && prevSHA != t.HeadSHA {
			if d, dErr := p.workspace.DiffCommits(jobCtx, wtDir, prevSHA, t.HeadSHA); dErr == nil && strings.TrimSpace(d) != "" {
				if len(repoCfg.IgnorePaths) > 0 {
					d, _ = repoconfig.FilterDiff(d, repoCfg.IgnorePaths)
				}
				if strings.TrimSpace(d) != "" {
					incDiff = d
					t.PreviousSHA = prevSHA
				}
			}
		}
	}

	// Scan intermediate commit patches + HEAD diff for leaked secrets (including deleted-before-HEAD).
	var secretFindings []security.Finding
	if wtDir != "" && p.workspace != nil && t.BaseRef != "" && t.HeadSHA != "" {
		patches, _ := p.workspace.CommitPatches(jobCtx, wtDir, t.BaseRef, t.HeadSHA)
		secretFindings = security.ScanPatches(patches, diff)
	} else {
		secretFindings = security.ScanPatches("", diff)
	}
	if len(secretFindings) > 0 {
		t.SecretAlerts = security.FormatMarkdownReport(secretFindings)
		p.events.Publish(events.Event{
			PRKey:   prKey,
			Type:    "secret_alert",
			Message: fmt.Sprintf("Detected %d secret finding(s) in PR commit history", len(secretFindings)),
		})
	}

	t.RepoInstructions = repoCfg.Instructions
	if pathInstr := repoCfg.InstructionsForPaths(repoconfig.ExtractChangedPaths(diff)); pathInstr != "" {
		t.RepoInstructions = strings.TrimSpace(t.RepoInstructions + "\n\n" + pathInstr)
	}
	if len(t.RepoSkills) == 0 {
		t.RepoSkills = repoCfg.Skills
	}
	t.RepoModel = repoCfg.Model

	// Checkout base branch worktree if available for differential AST/contract & sandbox comparison.
	var baseWtDir string
	if p.workspace != nil && t.CloneURL != "" && t.BaseRef != "" && wtDir != "" {
		var bw string
		var bClean func()
		var bErr error
		if t.DryRun {
			bw, bClean, bErr = p.workspace.CheckoutPRReadOnly(jobCtx, t.Owner, t.Repo, t.CloneURL, t.BaseRef)
		} else {
			bw, bClean, bErr = p.workspace.CheckoutPR(jobCtx, t.Owner, t.Repo, t.CloneURL, t.BaseRef)
		}
		if bErr == nil {
			baseWtDir = bw
			defer bClean()
		}
	}

	var stages []StageMetric
	detStart := time.Now()
	changedPaths := repoconfig.ExtractChangedPaths(diff)
	detReport := p.analysis.Run(analysis.Input{
		RepoSlug:      t.Owner + "/" + t.Repo,
		PRNumber:      t.PRNumber,
		BaseSHA:       t.BaseRef,
		HeadSHA:       t.HeadSHA,
		BaseWorktree:  baseWtDir,
		HeadWorktree:  wtDir,
		Diff:          diff,
		ChangedPaths:  changedPaths,
		ForbidImports: repoCfg.ForbidImports,
		DryRun:        t.DryRun,
	})
	detFindings, suppressedCount := p.memory.FilterFindings(t.Owner+"/"+t.Repo, detReport.Findings)
	out.SuppressedCount = suppressedCount

	var briefParts []string
	if detReport.SemanticDiff.FocusedBrief != "" {
		briefParts = append(briefParts, detReport.SemanticDiff.FocusedBrief)
	}
	if detReport.Brief != "" {
		briefParts = append(briefParts, detReport.Brief)
	}
	if p.opsIntel != nil {
		_, opsPrompt := p.opsIntel.Correlate(t.Owner+"/"+t.Repo, changedPaths)
		if opsPrompt != "" {
			briefParts = append(briefParts, opsPrompt)
		}
	}
	t.DeterministicBrief = strings.Join(briefParts, "\n")
	t.MemoryContext = p.memory.RelevantContext(t.Owner+"/"+t.Repo, changedPaths)
	recordStage(&stages, "deterministic_analysis", "completed", detStart, fmt.Sprintf("%d findings", len(detFindings)))

	// Deterministic short-circuit for trivial equivalent/docs-only automatic webhook PRs.
	if !t.Offline && !t.DryRun && t.Kind == "pr_review" && t.Command == "" &&
		detReport.SemanticDiff.OnlyEquivalentOrDocs && len(detFindings) == 0 && len(secretFindings) == 0 && t.DiffLineCount <= 30 {
		recordStage(&stages, "agent_investigation", "skipped", time.Now(), "short-circuited: equivalent/docs-only change")
		out.Model = "deterministic-short-circuit"
		out.Verdict = "COMMENT"
		out.Summary = "Automated check: changes are documentation/formatting-only with 0 deterministic or secret findings."
		out.Stages = stages
		out.DurationMs = time.Since(startedAt).Milliseconds()
		if p.gitea != nil && policy.CheckSideEffectAllowed(policy.EffectSetCommitStatus, perms) == nil {
			_ = p.gitea.SetCommitStatus(jobCtx, t.Owner, t.Repo, t.HeadSHA, "success", "CodeSpider: equivalent/docs-only check passed")
		}
		p.metrics.RecordRun(t.Kind, "success", 0, 0, 0, time.Since(startedAt))
		if p.store != nil {
			_ = p.store.RecordRun(store.RunRecord{
				PRKey: prKey, Kind: t.Kind, HeadSHA: t.HeadSHA, Model: out.Model, Verdict: out.Verdict,
				Stages: stageNames(stages), DurationMs: out.DurationMs, Status: "success", FinishedAt: time.Now().UTC(),
			})
		}
		return out, nil
	}

	// Offline deterministic mode: skip LLM and return/submit deterministic evidence directly.
	if t.Offline {
		out.Model = "offline-deterministic"
		out.Findings = append(out.Findings, detFindings...)
		out.SecretFindings = secretFindings
		out.Verdict = "COMMENT"
		for _, f := range detFindings {
			out.InlineComments = append(out.InlineComments, gitea.ReviewComment{
				Path:       f.Path,
				NewLineNum: f.EndLine,
				Body:       f.RenderInlineBody(),
			})
			if f.Severity == "critical" {
				out.Verdict = "REQUEST_CHANGES"
			}
		}
		if len(secretFindings) > 0 {
			out.Verdict = "REQUEST_CHANGES"
		}
		out.Summary = detReport.Brief
		if out.Summary == "" {
			out.Summary = "Offline deterministic review completed with 0 issues."
		}
		out.DurationMs = time.Since(startedAt).Milliseconds()
		return out, nil
	}

	var auditPtr *audit.Logger
	if !t.DryRun {
		auditPtr = p.audit
	}

	reg := tools.NewRegistry(tools.Params{
		WorktreeDir:           wtDir,
		BaseWorktreeDir:       baseWtDir,
		Workspace:             p.workspace,
		Gitea:                 p.gitea,
		Sandbox:               p.sandbox,
		Audit:                 auditPtr,
		Permissions:           &perms,
		Trigger:               t,
		Diff:                  diff,
		IncrementalDiff:       incDiff,
		PreviousSHA:           t.PreviousSHA,
		MinSeverity:           repoCfg.MinSeverity,
		DeterministicFindings: detFindings,
		VerifyHeadSHA: func(vCtx context.Context) error {
			return p.verifyHeadUnchanged(vCtx, t)
		},
		EnableWrite:      p.enableWrite && !t.DryRun,
		EnableProofOfBug: p.enableProofOfBug,
		DryRun:           t.DryRun,
		AuthorName:       p.authorName,
		OnToolCall: func(name, summary string) {
			p.events.Publish(events.Event{
				PRKey:   prKey,
				Type:    "tool_call",
				Tool:    name,
				Message: summary,
			})
		},
	})

	// Pre-agent SHA race check.
	if err := p.verifyHeadUnchanged(jobCtx, t); err != nil {
		p.logger.Warn("aborting stale review; remote PR head moved", "pr", prKey, "err", err)
		return out, err
	}

	agentStart := time.Now()
	res, err := p.agent.Run(jobCtx, t, reg)
	if err != nil {
		if !t.DryRun {
			p.finishWithError(prKey, t, startedAt, res.StepsUsed, res.TokensUsed, res.InlineComments, err)
		}
		return out, err
	}
	recordStage(&stages, "agent_investigation", "completed", agentStart, fmt.Sprintf("%d steps, %d tokens", res.StepsUsed, res.TokensUsed))

	// Post-agent SHA race check before any fallback posting or automations.
	if err := p.verifyHeadUnchanged(jobCtx, t); err != nil {
		p.logger.Warn("aborting post-agent publication; remote PR head moved", "pr", prKey, "err", err)
		if !t.DryRun {
			p.finishWithError(prKey, t, startedAt, res.StepsUsed, res.TokensUsed, res.InlineComments, context.Canceled)
		}
		return out, err
	}

	// If the agent never called submit_review on a PR review with deterministic findings, consolidate & flush them now.
	if !res.Submitted && t.Kind == "pr_review" && len(detFindings) > 0 {
		reg.ConsolidateFindings(detFindings, repoCfg.MinSeverity)
		if reg.State.CommentCount() > 0 {
			verdict := "COMMENT"
			if reg.State.HasCritical() {
				verdict = "REQUEST_CHANGES"
			}
			summary := strings.TrimSpace(res.FinalText)
			if summary == "" {
				summary = detReport.Brief
			}
			reg.State.StageSummary(summary, verdict)
			if flushErr := reg.FlushReview(jobCtx); flushErr != nil {
				if !t.DryRun {
					p.finishWithError(prKey, t, startedAt, res.StepsUsed, res.TokensUsed, res.InlineComments, flushErr)
				}
				return out, flushErr
			}
			res.Submitted = true
			res.InlineComments = reg.State.CommentCount()
			res.HasCritical = reg.State.HasCritical()
			res.Summary, res.Verdict = reg.State.FinalSummaryAndVerdict()
		}
	}

	// Fallback: if the agent returned text without calling submit_review/reply_comment, post it.
	if !t.DryRun && !res.Submitted && res.FinalText != "" && p.gitea != nil && policy.CheckSideEffectAllowed(policy.EffectPostComment, perms) == nil {
		if postErr := p.gitea.PostComment(jobCtx, t.Owner, t.Repo, t.PRNumber, res.FinalText); postErr != nil {
			p.finishWithError(prKey, t, startedAt, res.StepsUsed, res.TokensUsed, res.InlineComments, postErr)
			return out, postErr
		}
	}

	dur := time.Since(startedAt)
	out.Model = res.ModelUsed
	out.Verdict = res.Verdict
	out.Summary = res.Summary
	if out.Summary == "" {
		out.Summary = res.FinalText
	}
	out.InlineComments = reg.State.SnapshotComments()
	out.Findings = append(detFindings, reg.State.SnapshotFindings()...)
	out.SecretFindings = secretFindings
	out.Stages = stages
	out.StepsUsed = res.StepsUsed
	out.TokensUsed = res.TokensUsed
	out.BlueTeamRefuted = res.BlueTeamRefuted
	out.DurationMs = dur.Milliseconds()

	if !t.DryRun {
		p.runPostReviewAutomations(jobCtx, t, perms, repoCfg, diff, wtDir, prAuthor, res, secretFindings)

		if t.Kind == "pr_review" && p.gitea != nil && policy.CheckSideEffectAllowed(policy.EffectSetCommitStatus, perms) == nil {
			_ = p.gitea.SetCommitStatus(jobCtx, t.Owner, t.Repo, t.HeadSHA, "success",
				fmt.Sprintf("CodeSpider completed (%d inline comments)", res.InlineComments))
		}

		p.metrics.RecordRun(t.Kind, "success", res.StepsUsed, res.TokensUsed, res.InlineComments, dur)
		if p.store != nil {
			_ = p.store.RecordRun(store.RunRecord{
				PRKey:          prKey,
				Kind:           t.Kind,
				HeadSHA:        t.HeadSHA,
				Model:          res.ModelUsed,
				Verdict:        out.Verdict,
				StepsUsed:      res.StepsUsed,
				TokensUsed:     res.TokensUsed,
				InlineComments: res.InlineComments,
				Findings:       out.Findings,
				Stages:         stageNames(stages),
				DurationMs:     dur.Milliseconds(),
				Status:         "success",
				FinishedAt:     time.Now().UTC(),
			})
		}
	}

	p.logger.Info("completed agent run",
		"pr", prKey,
		"model", res.ModelUsed,
		"steps", res.StepsUsed,
		"tokens", res.TokensUsed,
		"inline_comments", res.InlineComments,
		"blue_team_refuted", res.BlueTeamRefuted,
		"duration_ms", dur.Milliseconds(),
	)
	return out, nil
}

func (p *Pool) buildHelpMessage() string {
	bot := p.authorName
	if bot == "" {
		bot = "codespider"
	}
	return fmt.Sprintf(`### CodeSpider Commands

- `+"`@%s /review`"+` — Force a fresh pull request review on the current commit.
- `+"`@%s /redteam`"+` — Run an adversarial Red-Team/Blue-Team security audit.
- `+"`@%s /summary`"+` — Generate a structured walkthrough and change summary for this PR.
- `+"`@%s /ci`"+` — Diagnose failing CI / commit status checks for this PR.
- `+"`@%s /fix <instructions>`"+` — Propose (or commit, when collaborator + write mode) targeted code fixes.
- `+"`@%s <question>`"+` — Ask any question about the PR diff or surrounding codebase.
- `+"`@%s /pause`"+` — Pause automatic reviews on this PR (collaborators only); `+"`/review`"+` still works.
- `+"`@%s /resume`"+` — Resume automatic reviews and review the current commit (collaborators only).
- `+"`@%s /resolve`"+` — Resolve all open CodeSpider inline review threads on this PR (collaborators only).
- `+"`@%s /help`"+` — Show this command reference.`, bot, bot, bot, bot, bot, bot, bot, bot, bot, bot)
}

func (p *Pool) finishWithError(prKey string, t gitea.ReviewTrigger, startedAt time.Time, steps, tokens, comments int, err error) {
	status := "failed"
	if errors.Is(err, context.Canceled) {
		status = "canceled"
	} else if t.Kind == "pr_review" && p.gitea != nil {
		_ = p.gitea.SetCommitStatus(context.Background(), t.Owner, t.Repo, t.HeadSHA, "error", "CodeSpider review failed")
	}

	dur := time.Since(startedAt)
	p.metrics.RecordRun(t.Kind, status, steps, tokens, comments, dur)
	p.logger.Error("agent run failed", "pr", prKey, "status", status, "err", err)
	if p.store != nil {
		_ = p.store.RecordRun(store.RunRecord{
			PRKey:          prKey,
			Kind:           t.Kind,
			HeadSHA:        t.HeadSHA,
			StepsUsed:      steps,
			TokensUsed:     tokens,
			InlineComments: comments,
			DurationMs:     dur.Milliseconds(),
			Status:         status,
			Error:          err.Error(),
			FinishedAt:     time.Now().UTC(),
		})
	}
}

func (p *Pool) registerActive(prKey string, cancel context.CancelFunc) uint64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	if prev, ok := p.active[prKey]; ok {
		prev.cancel()
	}
	p.nextJobID++
	id := p.nextJobID
	p.active[prKey] = activeJob{id: id, cancel: cancel}
	return id
}

func (p *Pool) clearActive(prKey string, id uint64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if cur, ok := p.active[prKey]; ok && cur.id == id {
		delete(p.active, prKey)
	}
}
