// Package tools implements the read-only codebase and forge action tools available to the agent.
package tools

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/Eresus-Security-OSS/CodeSpider/internal/audit"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/evidence"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/gitea"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/llm"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/policy"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/provider"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/sandbox"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/workspace"
)

// Handler executes a tool call with JSON arguments and returns a string observation.
type Handler func(ctx context.Context, rawArgs string) (string, error)

// ReviewState collects inline comments, structured evidence findings, and tracks review submission.
type ReviewState struct {
	mu             sync.Mutex
	InlineComments []gitea.ReviewComment
	Findings       []evidence.Finding
	OutOfDiffNotes []string
	Submitted      bool
	flushed        bool
	Summary        string
	Verdict        string
	hasCritical    bool
	seen           map[string]struct{}
}

// CommentCount returns the number of staged inline comments.
func (s *ReviewState) CommentCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.InlineComments)
}

// SnapshotComments returns a copy of currently staged inline comments.
func (s *ReviewState) SnapshotComments() []gitea.ReviewComment {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]gitea.ReviewComment, len(s.InlineComments))
	copy(out, s.InlineComments)
	return out
}

// SnapshotFindings returns a copy of structured evidence findings.
func (s *ReviewState) SnapshotFindings() []evidence.Finding {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]evidence.Finding, len(s.Findings))
	copy(out, s.Findings)
	return out
}

// RemoveCommentsByIndices removes staged inline comments at the specified 0-based indices
// and marks matching Findings as refuted with counter-evidence.
func (s *ReviewState) RemoveCommentsByIndices(indices []int) {
	if len(indices) == 0 {
		return
	}
	drop := make(map[int]bool, len(indices))
	for _, idx := range indices {
		drop[idx] = true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	kept := make([]gitea.ReviewComment, 0, len(s.InlineComments))
	for i, c := range s.InlineComments {
		if !drop[i] {
			kept = append(kept, c)
		}
	}
	s.InlineComments = kept
	for i := range s.Findings {
		if drop[i] {
			s.Findings[i].State = evidence.StateRefuted
		}
	}
}

// MarkCorroborated updates staged inline comments at the given indices to model_corroborated
// without claiming formal proof.
func (s *ReviewState) MarkCorroborated(indices []int) {
	if len(indices) == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, idx := range indices {
		if idx >= 0 && idx < len(s.InlineComments) {
			if !strings.Contains(s.InlineComments[idx].Body, "[MODEL CORROBORATED]") {
				s.InlineComments[idx].Body = "**[MODEL CORROBORATED]** " + s.InlineComments[idx].Body
			}
			if idx < len(s.Findings) {
				s.Findings[idx].State = evidence.StateModelCorroborated
			}
		}
	}
}

// MarkVerified is retained as an alias for MarkCorroborated.
func (s *ReviewState) MarkVerified(indices []int) {
	s.MarkCorroborated(indices)
}

// FinalSummaryAndVerdict returns the submitted summary and verdict.
func (s *ReviewState) FinalSummaryAndVerdict() (string, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.Summary, s.Verdict
}

// StageSummary sets the summary and verdict and marks the review submitted for FlushReview.
func (s *ReviewState) StageSummary(summary, verdict string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Summary = summary
	s.Verdict = verdict
	s.Submitted = true
}

// IsSubmitted reports whether submit_review or reply_comment succeeded.
func (s *ReviewState) IsSubmitted() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.Submitted
}

// HasCritical reports whether any staged inline comment was marked critical.
func (s *ReviewState) HasCritical() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hasCritical
}

// Registry holds tool definitions and handlers for a single agent run.
type Registry struct {
	defs        []llm.ToolDefinition
	handlers    map[string]Handler
	params      Params
	deferSubmit bool
	State       *ReviewState
}

// SetDeferSubmit controls whether submit_review defers the forge API call until FlushReview.
func (r *Registry) SetDeferSubmit(deferIt bool) {
	r.deferSubmit = deferIt
}

// Params bundles dependencies needed to construct a per-PR tool registry.
type Params struct {
	WorktreeDir           string
	BaseWorktreeDir       string
	Workspace             *workspace.Manager
	Gitea                 *gitea.Client
	Forge                 provider.ForgeProvider
	Sandbox               *sandbox.Executor
	Audit                 *audit.Logger
	Permissions           *policy.PermissionSet
	Trigger               gitea.ReviewTrigger
	Diff                  string
	IncrementalDiff       string
	PreviousSHA           string
	MinSeverity           string
	DeterministicFindings []evidence.Finding
	VerifyHeadSHA         func(ctx context.Context) error
	EnableWrite           bool
	EnableProofOfBug      bool
	DryRun                bool
	AuthorName            string
	OnToolCall            func(name, summary string)
}

// NewRegistry builds the toolset for a PR review or comment-reply run.
func NewRegistry(p Params) *Registry {
	if p.Forge == nil && p.Gitea != nil {
		p.Forge = &provider.GiteaAdapter{Client: p.Gitea}
	}
	reg := &Registry{
		handlers: make(map[string]Handler),
		params:   p,
		State:    &ReviewState{},
	}
	validLines := ParseDiffValidLines(p.Diff)

	annotatedDiff := AnnotateDiff(p.Diff)
	reg.register("get_pr_diff",
		"Return the unified diff of the pull request with [L<num>] new-file line annotations. Supports optional line offset and limit for large diffs.",
		schema(map[string]any{
			"offset": prop("integer", "1-based line offset (default 1)"),
			"limit":  prop("integer", "Max lines to return (default 400)"),
		}, nil),
		func(ctx context.Context, raw string) (string, error) {
			var args struct {
				Offset int `json:"offset"`
				Limit  int `json:"limit"`
			}
			_ = json.Unmarshal([]byte(raw), &args)
			return sliceLines(annotatedDiff, args.Offset, args.Limit, 400), nil
		},
	)

	if strings.TrimSpace(p.IncrementalDiff) != "" {
		annotatedInc := AnnotateDiff(p.IncrementalDiff)
		reg.register("get_incremental_diff",
			fmt.Sprintf("Return only the diff introduced since the previously reviewed commit (%s..%s) with [L<num>] line annotations.", p.PreviousSHA, p.Trigger.HeadSHA),
			schema(map[string]any{
				"offset": prop("integer", "1-based line offset (default 1)"),
				"limit":  prop("integer", "Max lines to return (default 400)"),
			}, nil),
			func(ctx context.Context, raw string) (string, error) {
				var args struct {
					Offset int `json:"offset"`
					Limit  int `json:"limit"`
				}
				_ = json.Unmarshal([]byte(raw), &args)
				return sliceLines(annotatedInc, args.Offset, args.Limit, 400), nil
			},
		)
	}

	reg.register("list_files",
		"List file paths inside the PR worktree (excluding .git, node_modules, vendor).",
		schema(map[string]any{
			"subpath": prop("string", "Optional subdirectory to list"),
			"glob":    prop("string", "Optional filename glob pattern (e.g. *.go)"),
		}, nil),
		func(ctx context.Context, raw string) (string, error) {
			var args struct {
				Subpath string `json:"subpath"`
				Glob    string `json:"glob"`
			}
			if strings.TrimSpace(raw) != "" {
				if err := json.Unmarshal([]byte(raw), &args); err != nil {
					return "", err
				}
			}
			if p.WorktreeDir == "" {
				return "", fmt.Errorf("worktree not available")
			}
			root := p.WorktreeDir
			if args.Subpath != "" {
				var err error
				root, err = workspace.ResolveSafePath(p.WorktreeDir, args.Subpath)
				if err != nil {
					return "", err
				}
			}
			return listRepoFiles(ctx, p.WorktreeDir, root, args.Glob, 200)
		},
	)

	reg.register("read_file",
		"Read lines from a file inside the PR worktree.",
		schema(map[string]any{
			"path":       prop("string", "Relative path inside repository"),
			"start_line": prop("integer", "1-based start line (default 1)"),
			"end_line":   prop("integer", "1-based end line (default start_line+200)"),
		}, []string{"path"}),
		func(ctx context.Context, raw string) (string, error) {
			var args struct {
				Path      string `json:"path"`
				StartLine int    `json:"start_line"`
				EndLine   int    `json:"end_line"`
			}
			if err := json.Unmarshal([]byte(raw), &args); err != nil {
				return "", err
			}
			if p.WorktreeDir == "" {
				return "", fmt.Errorf("worktree not available")
			}
			data, err := workspace.ReadSafeFile(p.WorktreeDir, args.Path, 2<<20)
			if err != nil {
				return "", err
			}
			start := args.StartLine
			if start < 1 {
				start = 1
			}
			limit := 200
			if args.EndLine >= start {
				limit = args.EndLine - start + 1
				if limit > 400 {
					limit = 400
				}
			}
			return sliceLines(string(data), start, limit, 200), nil
		},
	)

	reg.register("search_code",
		"Search repository files in the PR worktree for a regex or substring pattern.",
		schema(map[string]any{
			"pattern": prop("string", "Search pattern (Go regexp)"),
			"subpath": prop("string", "Optional subdirectory to restrict search"),
		}, []string{"pattern"}),
		func(ctx context.Context, raw string) (string, error) {
			var args struct {
				Pattern string `json:"pattern"`
				Subpath string `json:"subpath"`
			}
			if err := json.Unmarshal([]byte(raw), &args); err != nil {
				return "", err
			}
			if p.WorktreeDir == "" {
				return "", fmt.Errorf("worktree not available")
			}
			root := p.WorktreeDir
			if args.Subpath != "" {
				var err error
				root, err = workspace.ResolveSafePath(p.WorktreeDir, args.Subpath)
				if err != nil {
					return "", err
				}
			}
			return searchRepo(ctx, p.WorktreeDir, root, args.Pattern, 50)
		},
	)

	reg.register("list_pr_comments",
		"List existing conversation comments on this pull request.",
		schema(map[string]any{}, nil),
		func(ctx context.Context, raw string) (string, error) {
			if p.Forge == nil {
				return "[]", nil
			}
			comments, err := p.Forge.ListPRComments(ctx, p.Trigger.Owner, p.Trigger.Repo, p.Trigger.PRNumber)
			if err != nil {
				return "", err
			}
			b, _ := json.Marshal(comments)
			return string(b), nil
		},
	)

	reg.register("list_pr_reviews",
		"List existing formal PR reviews on this pull request.",
		schema(map[string]any{}, nil),
		func(ctx context.Context, raw string) (string, error) {
			if p.Forge == nil {
				return "[]", nil
			}
			reviews, err := p.Forge.ListPullReviews(ctx, p.Trigger.Owner, p.Trigger.Repo, p.Trigger.PRNumber)
			if err != nil {
				return "", err
			}
			b, _ := json.Marshal(reviews)
			return string(b), nil
		},
	)

	reg.register("add_inline_comment",
		"Stage an inline review comment on a specific file and new line number. Call submit_review when finished.",
		schema(map[string]any{
			"path":       prop("string", "File path relative to repo root"),
			"line":       prop("integer", "1-based end/target line number in the new version of the file"),
			"start_line": prop("integer", "Optional 1-based start line for multi-line suggestions"),
			"severity":   prop("string", "info, warning, or critical"),
			"body":       prop("string", "Concise, actionable review comment"),
			"suggestion": prop("string", "Optional replacement code for the target line(s), rendered as an inline suggestion block without markdown fences"),
		}, []string{"path", "line", "body"}),
		func(ctx context.Context, raw string) (string, error) {
			var args struct {
				Path       string `json:"path"`
				Line       int64  `json:"line"`
				StartLine  int64  `json:"start_line"`
				Severity   string `json:"severity"`
				Body       string `json:"body"`
				Suggestion string `json:"suggestion"`
			}
			if err := json.Unmarshal([]byte(raw), &args); err != nil {
				return "", err
			}
			if args.Path == "" || args.Line < 1 || strings.TrimSpace(args.Body) == "" {
				return "", fmt.Errorf("path, line >= 1, and body are required")
			}
			if p.MinSeverity != "" && severityRank(args.Severity) < severityRank(p.MinSeverity) {
				return fmt.Sprintf("skipped comment on %s:%d (severity %q is below repo min_severity %q)", args.Path, args.Line, args.Severity, p.MinSeverity), nil
			}
			body := args.Body
			if args.StartLine > 0 && args.StartLine < args.Line {
				body = fmt.Sprintf("*(Lines %d–%d)* %s", args.StartLine, args.Line, body)
			}
			if args.Severity != "" {
				body = fmt.Sprintf("**[%s]** %s", strings.ToUpper(args.Severity), body)
			}
			if sug := stripCodeFences(args.Suggestion); sug != "" {
				body = fmt.Sprintf("%s\n\n```suggestion\n%s\n```", body, sug)
			}

			// Diff hunk gate: if the diff has explicit hunks and line is outside them,
			// move the finding into summary notes rather than failing forge review creation.
			if len(validLines) > 0 && !isLineInDiff(validLines, args.Path, args.Line) {
				reg.State.mu.Lock()
				if strings.EqualFold(strings.TrimSpace(args.Severity), "critical") {
					reg.State.hasCritical = true
				}
				reg.State.OutOfDiffNotes = append(reg.State.OutOfDiffNotes, fmt.Sprintf("- **%s:%d** — %s", args.Path, args.Line, body))
				reg.State.mu.Unlock()
				return fmt.Sprintf("line %s:%d is outside diff hunks; recorded in review summary notes", args.Path, args.Line), nil
			}

			dedupKey := fmt.Sprintf("%s:%d:%s", args.Path, args.Line, body)
			reg.State.mu.Lock()
			if reg.State.seen == nil {
				reg.State.seen = make(map[string]struct{})
			}
			if _, exists := reg.State.seen[dedupKey]; exists {
				reg.State.mu.Unlock()
				return fmt.Sprintf("duplicate inline comment on %s:%d skipped", args.Path, args.Line), nil
			}
			reg.State.seen[dedupKey] = struct{}{}
			if strings.EqualFold(strings.TrimSpace(args.Severity), "critical") {
				reg.State.hasCritical = true
			}
			reg.State.InlineComments = append(reg.State.InlineComments, gitea.ReviewComment{
				Path:       args.Path,
				NewLineNum: args.Line,
				Body:       body,
			})
			f := evidence.Finding{
				Fingerprint: evidence.ComputeFingerprint("CS-LLM-001", "agent", args.Path, fmt.Sprintf("%s:%d", args.Path, args.Line)),
				RuleID:      "CS-LLM-001",
				Category:    "agent",
				Severity:    strings.ToLower(strings.TrimSpace(args.Severity)),
				State:       evidence.StateCandidate,
				Path:        args.Path,
				StartLine:   args.StartLine,
				EndLine:     args.Line,
				CommitSHA:   p.Trigger.HeadSHA,
				Body:        args.Body,
				Suggestion:  stripCodeFences(args.Suggestion),
			}
			reg.State.Findings = append(reg.State.Findings, f)
			count := len(reg.State.InlineComments)
			reg.State.mu.Unlock()
			return fmt.Sprintf("staged inline comment #%d on %s:%d", count, args.Path, args.Line), nil
		},
	)

	reg.register("submit_review",
		"Submit the final PR review (summary + all staged inline comments) to the configured forge.",
		schema(map[string]any{
			"verdict": prop("string", "COMMENT, APPROVE, or REQUEST_CHANGES"),
			"summary": prop("string", "Markdown summary of the PR review"),
		}, []string{"summary"}),
		func(ctx context.Context, raw string) (string, error) {
			var args struct {
				Verdict string `json:"verdict"`
				Summary string `json:"summary"`
			}
			if err := json.Unmarshal([]byte(raw), &args); err != nil {
				return "", err
			}
			verdict := strings.ToUpper(strings.TrimSpace(args.Verdict))
			if verdict != "APPROVE" && verdict != "REQUEST_CHANGES" {
				verdict = "COMMENT"
			}
			reg.State.mu.Lock()
			reg.State.Summary = args.Summary
			reg.State.Verdict = verdict
			reg.State.Submitted = true
			reg.State.mu.Unlock()

			if reg.deferSubmit {
				return fmt.Sprintf("staged review (%s) for verification", verdict), nil
			}
			if err := reg.FlushReview(ctx); err != nil {
				reg.State.mu.Lock()
				reg.State.Submitted = false
				reg.State.mu.Unlock()
				return "", err
			}
			return fmt.Sprintf("submitted review (%s) with %d inline comments", verdict, reg.State.CommentCount()), nil
		},
	)

	reg.register("reply_comment",
		"Post a direct reply comment on the PR conversation thread (use when answering @mentions).",
		schema(map[string]any{
			"body": prop("string", "Markdown reply body"),
		}, []string{"body"}),
		func(ctx context.Context, raw string) (string, error) {
			var args struct {
				Body string `json:"body"`
			}
			if err := json.Unmarshal([]byte(raw), &args); err != nil {
				return "", err
			}
			if strings.TrimSpace(args.Body) == "" {
				return "", fmt.Errorf("body is required")
			}
			if !p.DryRun && p.Forge != nil {
				if p.Permissions != nil {
					if err := policy.CheckSideEffectAllowed(policy.EffectPostComment, *p.Permissions); err != nil {
						return "", err
					}
				}
				if p.VerifyHeadSHA != nil {
					if err := p.VerifyHeadSHA(ctx); err != nil {
						return "", err
					}
				}
				if err := p.Forge.PostComment(ctx, p.Trigger.Owner, p.Trigger.Repo, p.Trigger.PRNumber, args.Body); err != nil {
					return "", err
				}
			}
			reg.State.mu.Lock()
			reg.State.Submitted = true
			reg.State.flushed = true
			reg.State.Summary = args.Body
			reg.State.mu.Unlock()
			return "posted reply comment", nil
		},
	)

	reg.registerAdvancedTools(p)

	if p.EnableWrite {
		reg.registerWriteTools(p)
	}

	return reg
}

// ConsolidateFindings merges statically supported deterministic findings into ReviewState
// without duplicating LLM comments already targeting the same file/line, and upgrades Verdict on criticals.
func (r *Registry) ConsolidateFindings(detFindings []evidence.Finding, minSeverity string) {
	if len(detFindings) == 0 {
		return
	}
	validLines := ParseDiffValidLines(r.params.Diff)

	r.State.mu.Lock()
	defer r.State.mu.Unlock()

	for _, df := range detFindings {
		if minSeverity != "" && severityRank(df.Severity) < severityRank(minSeverity) {
			continue
		}
		if strings.EqualFold(df.Severity, "critical") {
			r.State.hasCritical = true
		}

		// Check if an existing LLM comment already covers the same file and nearby line (+/- 3).
		matched := false
		for i := range r.State.InlineComments {
			c := &r.State.InlineComments[i]
			if filepath.ToSlash(c.Path) == filepath.ToSlash(df.Path) && absInt64(c.NewLineNum-df.EndLine) <= 3 {
				if !strings.Contains(c.Body, "[STATICALLY SUPPORTED]") {
					c.Body = "**[STATICALLY SUPPORTED]** " + c.Body
				}
				if i < len(r.State.Findings) {
					r.State.Findings[i].State = evidence.StateStaticallySupported
					r.State.Findings[i].Evidence = append(r.State.Findings[i].Evidence, df.Evidence...)
				}
				matched = true
				break
			}
		}
		if matched {
			continue
		}

		body := df.RenderInlineBody()
		if len(validLines) > 0 && !isLineInDiff(validLines, df.Path, df.EndLine) {
			r.State.OutOfDiffNotes = append(r.State.OutOfDiffNotes, fmt.Sprintf("- **%s:%d** — %s", df.Path, df.EndLine, body))
			continue
		}

		if r.State.seen == nil {
			r.State.seen = make(map[string]struct{})
		}
		dedupKey := fmt.Sprintf("%s:%d:%s", df.Path, df.EndLine, df.RuleID)
		if _, exists := r.State.seen[dedupKey]; exists {
			continue
		}
		r.State.seen[dedupKey] = struct{}{}
		r.State.InlineComments = append(r.State.InlineComments, gitea.ReviewComment{
			Path:       df.Path,
			NewLineNum: df.EndLine,
			Body:       body,
		})
		r.State.Findings = append(r.State.Findings, df)
	}

	if r.State.hasCritical && (r.State.Verdict == "" || r.State.Verdict == "COMMENT" || r.State.Verdict == "APPROVE") {
		r.State.Verdict = "REQUEST_CHANGES"
	}
}

func absInt64(v int64) int64 {
	if v < 0 {
		return -v
	}
	return v
}

// FlushReview sends a staged PR review to the configured forge if it has not been flushed yet and DryRun is false.
// It consolidates deterministic findings and verifies the remote PR head SHA before publication.
func (r *Registry) FlushReview(ctx context.Context) error {
	r.ConsolidateFindings(r.params.DeterministicFindings, r.params.MinSeverity)

	r.State.mu.Lock()
	if !r.State.Submitted || r.State.flushed {
		r.State.mu.Unlock()
		return nil
	}
	summary := r.State.Summary
	if len(r.State.OutOfDiffNotes) > 0 {
		summary = strings.TrimSpace(summary) + "\n\n### Additional Findings (Outside Diff Hunks)\n" + strings.Join(r.State.OutOfDiffNotes, "\n")
	}
	verdict := r.State.Verdict
	if verdict == "" {
		verdict = "COMMENT"
	}
	comments := append([]gitea.ReviewComment(nil), r.State.InlineComments...)
	r.State.mu.Unlock()

	if !r.params.DryRun && r.params.Forge != nil {
		if r.params.Permissions != nil {
			if err := policy.CheckSideEffectAllowed(policy.EffectPostReview, *r.params.Permissions); err != nil {
				return err
			}
		}
		if r.params.VerifyHeadSHA != nil {
			if err := r.params.VerifyHeadSHA(ctx); err != nil {
				return err
			}
		}
		err := r.params.Forge.SubmitReview(ctx, r.params.Trigger.Owner, r.params.Trigger.Repo, r.params.Trigger.PRNumber, gitea.CreateReviewRequest{
			CommitID: r.params.Trigger.HeadSHA,
			Body:     summary,
			Event:    verdict,
			Comments: comments,
		})
		if err != nil {
			return err
		}
	}

	r.State.mu.Lock()
	r.State.Summary = summary
	r.State.flushed = true
	r.State.mu.Unlock()
	return nil
}

func (r *Registry) registerWriteTools(p Params) {
	r.register("write_file",
		"Create or overwrite a file inside the PR worktree. Blocked from writing inside .git.",
		schema(map[string]any{
			"path":    prop("string", "Relative path inside repository"),
			"content": prop("string", "Full file content to write"),
		}, []string{"path", "content"}),
		func(ctx context.Context, raw string) (string, error) {
			var args struct {
				Path    string `json:"path"`
				Content string `json:"content"`
			}
			if err := json.Unmarshal([]byte(raw), &args); err != nil {
				return "", err
			}
			if err := workspace.WriteSafeFile(p.WorktreeDir, args.Path, []byte(args.Content)); err != nil {
				return "", err
			}
			return fmt.Sprintf("wrote %d bytes to %s", len(args.Content), args.Path), nil
		},
	)

	r.register("edit_file",
		"Replace an exact unique substring in a file inside the PR worktree.",
		schema(map[string]any{
			"path":     prop("string", "Relative path inside repository"),
			"old_text": prop("string", "Exact existing text to replace"),
			"new_text": prop("string", "Replacement text"),
		}, []string{"path", "old_text", "new_text"}),
		func(ctx context.Context, raw string) (string, error) {
			var args struct {
				Path    string `json:"path"`
				OldText string `json:"old_text"`
				NewText string `json:"new_text"`
			}
			if err := json.Unmarshal([]byte(raw), &args); err != nil {
				return "", err
			}
			if args.OldText == "" {
				return "", fmt.Errorf("old_text must not be empty")
			}
			rawBytes, err := workspace.ReadSafeFile(p.WorktreeDir, args.Path, 2<<20)
			if err != nil {
				return "", err
			}
			content := string(rawBytes)
			count := strings.Count(content, args.OldText)
			if count == 0 {
				return "", fmt.Errorf("old_text not found in %s", args.Path)
			}
			if count > 1 {
				return "", fmt.Errorf("old_text matched %d times in %s; provide more context", count, args.Path)
			}
			updated := strings.Replace(content, args.OldText, args.NewText, 1)
			if err := workspace.WriteSafeFile(p.WorktreeDir, args.Path, []byte(updated)); err != nil {
				return "", err
			}
			return fmt.Sprintf("edited %s", args.Path), nil
		},
	)

	r.register("commit_and_push",
		"Stage all changes in the PR worktree, commit them, and push to the configured forge's PR head branch.",
		schema(map[string]any{
			"message": prop("string", "Git commit message"),
		}, []string{"message"}),
		func(ctx context.Context, raw string) (string, error) {
			var args struct {
				Message string `json:"message"`
			}
			if err := json.Unmarshal([]byte(raw), &args); err != nil {
				return "", err
			}
			if p.Workspace == nil {
				return "", fmt.Errorf("workspace manager not configured")
			}
			if p.Permissions != nil {
				if err := policy.CheckSideEffectAllowed(policy.EffectGitPush, *p.Permissions); err != nil {
					return "", err
				}
			}
			if p.VerifyHeadSHA != nil {
				if err := p.VerifyHeadSHA(ctx); err != nil {
					return "", err
				}
			}
			newSHA, err := p.Workspace.CommitAndPushWithGuard(ctx, p.WorktreeDir, p.Trigger.CloneURL, p.Trigger.HeadRef, p.Trigger.HeadSHA, p.AuthorName, args.Message)
			if err != nil {
				return "", err
			}
			return fmt.Sprintf("committed and pushed %s to %s", newSHA, p.Trigger.HeadRef), nil
		},
	)
}

func resolveWritablePath(worktreeDir, relPath string) (string, error) {
	if worktreeDir == "" {
		return "", fmt.Errorf("worktree not available")
	}
	clean := filepath.ToSlash(filepath.Clean(relPath))
	if clean == ".git" || strings.HasPrefix(clean, ".git/") || strings.Contains(clean, "/.git/") {
		return "", fmt.Errorf("refusing to write inside .git: %s", relPath)
	}
	return workspace.ResolveSafePath(worktreeDir, relPath)
}

// Definitions returns all registered tool definitions for the LLM.
func (r *Registry) Definitions() []llm.ToolDefinition {
	return r.defs
}

// Execute runs a named tool after enforcing capability-based authorization and audit logging.
func (r *Registry) Execute(ctx context.Context, name, rawArgs string) (string, error) {
	if r.params.Permissions != nil {
		if err := policy.CheckToolAllowed(name, *r.params.Permissions); err != nil {
			r.params.Audit.Log(audit.Event{
				Actor:    r.params.Trigger.CommentBy,
				PRKey:    fmt.Sprintf("%s/%s#%d", r.params.Trigger.Owner, r.params.Trigger.Repo, r.params.Trigger.PRNumber),
				Action:   "tool:" + name,
				Decision: "deny",
				Reason:   err.Error(),
			})
			return "", err
		}
	}
	h, ok := r.handlers[name]
	if !ok {
		return "", fmt.Errorf("unknown tool: %s", name)
	}
	if r.params.OnToolCall != nil {
		summary := strings.TrimSpace(rawArgs)
		if len(summary) > 120 {
			summary = summary[:120] + "..."
		}
		r.params.OnToolCall(name, summary)
	}
	return h(ctx, rawArgs)
}

func (r *Registry) register(name, desc string, params any, h Handler) {
	r.defs = append(r.defs, llm.ToolDefinition{
		Type: "function",
		Function: llm.FunctionDefinition{
			Name:        name,
			Description: desc,
			Parameters:  params,
		},
	})
	r.handlers[name] = h
}

func schema(props map[string]any, required []string) map[string]any {
	s := map[string]any{
		"type":       "object",
		"properties": props,
	}
	if len(required) > 0 {
		s["required"] = required
	}
	return s
}

func prop(typ, desc string) map[string]any {
	return map[string]any{
		"type":        typ,
		"description": desc,
	}
}

func stripCodeFences(s string) string {
	s = strings.TrimRight(s, "\r\n")
	trimmed := strings.TrimSpace(s)
	if trimmed == "" {
		return ""
	}
	if strings.HasPrefix(trimmed, "```") {
		if nl := strings.Index(trimmed, "\n"); nl != -1 {
			trimmed = trimmed[nl+1:]
		}
		if idx := strings.LastIndex(trimmed, "```"); idx != -1 {
			trimmed = trimmed[:idx]
		}
		return strings.TrimRight(trimmed, "\r\n")
	}
	return s
}

func sliceLines(text string, offset, limit, defaultLimit int) string {
	if offset < 1 {
		offset = 1
	}
	if limit <= 0 {
		limit = defaultLimit
	}
	lines := strings.Split(text, "\n")
	if offset > len(lines) {
		return "(EOF)"
	}
	end := offset - 1 + limit
	if end > len(lines) {
		end = len(lines)
	}
	var b strings.Builder
	for i := offset - 1; i < end; i++ {
		fmt.Fprintf(&b, "%d: %s\n", i+1, lines[i])
	}
	if end < len(lines) {
		fmt.Fprintf(&b, "... (%d more lines)\n", len(lines)-end)
	}
	return b.String()
}

func searchRepo(ctx context.Context, worktreeRoot, searchRoot, pattern string, maxMatches int) (string, error) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return "", fmt.Errorf("invalid regex %q: %w", pattern, err)
	}
	var out strings.Builder
	matches := 0
	walkErr := filepath.WalkDir(searchRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if d.IsDir() {
			if strings.EqualFold(d.Name(), ".git") || d.Name() == "node_modules" || d.Name() == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		info, err := d.Info()
		if err != nil || info.Size() > 512*1024 {
			return nil
		}
		rel, err := filepath.Rel(worktreeRoot, path)
		if err != nil {
			return nil
		}
		raw, err := workspace.ReadSafeFile(worktreeRoot, rel, 512*1024)
		if err != nil {
			return nil
		}

		sc := bufio.NewScanner(strings.NewReader(string(raw)))
		lineNo := 0
		for sc.Scan() {
			lineNo++
			line := sc.Text()
			if re.MatchString(line) {
				fmt.Fprintf(&out, "%s:%d: %s\n", rel, lineNo, strings.TrimSpace(line))
				matches++
				if matches >= maxMatches {
					return fs.SkipAll
				}
			}
		}
		return nil
	})
	if walkErr != nil && walkErr != fs.SkipAll {
		return "", walkErr
	}
	if matches == 0 {
		return "no matches found", nil
	}
	return out.String(), nil
}

var hunkHeaderRe = regexp.MustCompile(`^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@`)

// AnnotateDiff prefixes unified diff lines with [L<newLine>] or [DEL] so inline comments
// can reference exact new-file line numbers.
func AnnotateDiff(diff string) string {
	if diff == "" {
		return ""
	}
	lines := strings.Split(diff, "\n")
	out := make([]string, 0, len(lines))
	inHunk := false
	newLine := 0

	for _, line := range lines {
		if strings.HasPrefix(line, "diff --git ") {
			inHunk = false
			out = append(out, line)
			continue
		}
		if m := hunkHeaderRe.FindStringSubmatch(line); m != nil {
			n, err := strconv.Atoi(m[1])
			if err == nil {
				newLine = n
				inHunk = true
			}
			out = append(out, line)
			continue
		}
		if !inHunk {
			out = append(out, line)
			continue
		}
		switch {
		case strings.HasPrefix(line, "+++ ") || strings.HasPrefix(line, "--- ") || strings.HasPrefix(line, "\\"):
			out = append(out, line)
		case strings.HasPrefix(line, "+"):
			out = append(out, fmt.Sprintf("[L%d] %s", newLine, line))
			newLine++
		case strings.HasPrefix(line, "-"):
			out = append(out, fmt.Sprintf("[DEL] %s", line))
		case strings.HasPrefix(line, " "):
			out = append(out, fmt.Sprintf("[L%d] %s", newLine, line))
			newLine++
		default:
			out = append(out, line)
		}
	}
	return strings.Join(out, "\n")
}

func severityRank(s string) int {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return 3
	case "warning":
		return 2
	default:
		return 1
	}
}

func listRepoFiles(ctx context.Context, worktreeRoot, searchRoot, globPat string, maxFiles int) (string, error) {
	var out strings.Builder
	count := 0
	walkErr := filepath.WalkDir(searchRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if d.IsDir() {
			if strings.EqualFold(d.Name(), ".git") || d.Name() == "node_modules" || d.Name() == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		rel, err := filepath.Rel(worktreeRoot, path)
		if err != nil {
			return nil
		}
		relSlash := filepath.ToSlash(rel)
		if globPat != "" {
			okBase, _ := filepath.Match(globPat, d.Name())
			okFull, _ := filepath.Match(globPat, relSlash)
			if !okBase && !okFull {
				return nil
			}
		}
		out.WriteString(relSlash)
		out.WriteByte('\n')
		count++
		if count >= maxFiles {
			return fs.SkipAll
		}
		return nil
	})
	if walkErr != nil && walkErr != fs.SkipAll {
		return "", walkErr
	}
	if count == 0 {
		return "no files found", nil
	}
	return out.String(), nil
}
