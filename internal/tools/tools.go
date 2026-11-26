// Package tools implements the read-only codebase and Gitea action tools available to the agent.
package tools

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/Eresus-Security-OSS/CodeSpider/internal/gitea"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/llm"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/workspace"
)

// Handler executes a tool call with JSON arguments and returns a string observation.
type Handler func(ctx context.Context, rawArgs string) (string, error)

// ReviewState collects inline comments and tracks whether the agent submitted a final Gitea action.
type ReviewState struct {
	mu             sync.Mutex
	InlineComments []gitea.ReviewComment
	Submitted      bool
	Summary        string
}

// Registry holds tool definitions and handlers for a single agent run.
type Registry struct {
	defs     []llm.ToolDefinition
	handlers map[string]Handler
	State    *ReviewState
}

// Params bundles dependencies needed to construct a per-PR tool registry.
type Params struct {
	WorktreeDir string
	Workspace   *workspace.Manager
	Gitea       *gitea.Client
	Trigger     gitea.ReviewTrigger
	Diff        string
	EnableWrite bool
	AuthorName  string
}

// NewRegistry builds the toolset for a PR review or comment-reply run.
func NewRegistry(p Params) *Registry {
	reg := &Registry{
		handlers: make(map[string]Handler),
		State:    &ReviewState{},
	}

	reg.register("get_pr_diff",
		"Return the unified diff of the pull request. Supports optional line offset and limit for large diffs.",
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
			return sliceLines(p.Diff, args.Offset, args.Limit, 400), nil
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
			full, err := workspace.ResolveSafePath(p.WorktreeDir, args.Path)
			if err != nil {
				return "", err
			}
			data, err := os.ReadFile(full)
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
			if p.Gitea == nil {
				return "[]", nil
			}
			comments, err := p.Gitea.ListPRComments(ctx, p.Trigger.Owner, p.Trigger.Repo, p.Trigger.PRNumber)
			if err != nil {
				return "", err
			}
			b, _ := json.Marshal(comments)
			return string(b), nil
		},
	)

	reg.register("add_inline_comment",
		"Stage an inline review comment on a specific file and new line number. Call submit_review when finished.",
		schema(map[string]any{
			"path":     prop("string", "File path relative to repo root"),
			"line":     prop("integer", "1-based line number in the new version of the file"),
			"severity": prop("string", "info, warning, or critical"),
			"body":     prop("string", "Concise, actionable review comment"),
		}, []string{"path", "line", "body"}),
		func(ctx context.Context, raw string) (string, error) {
			var args struct {
				Path     string `json:"path"`
				Line     int64  `json:"line"`
				Severity string `json:"severity"`
				Body     string `json:"body"`
			}
			if err := json.Unmarshal([]byte(raw), &args); err != nil {
				return "", err
			}
			if args.Path == "" || args.Line < 1 || strings.TrimSpace(args.Body) == "" {
				return "", fmt.Errorf("path, line >= 1, and body are required")
			}
			body := args.Body
			if args.Severity != "" {
				body = fmt.Sprintf("**[%s]** %s", strings.ToUpper(args.Severity), body)
			}
			reg.State.mu.Lock()
			reg.State.InlineComments = append(reg.State.InlineComments, gitea.ReviewComment{
				Path:       args.Path,
				NewLineNum: args.Line,
				Body:       body,
			})
			count := len(reg.State.InlineComments)
			reg.State.mu.Unlock()
			return fmt.Sprintf("staged inline comment #%d on %s:%d", count, args.Path, args.Line), nil
		},
	)

	reg.register("submit_review",
		"Submit the final PR review (summary + all staged inline comments) to Gitea.",
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
			comments := append([]gitea.ReviewComment(nil), reg.State.InlineComments...)
			reg.State.Summary = args.Summary
			reg.State.mu.Unlock()

			if p.Gitea != nil {
				err := p.Gitea.CreateReview(ctx, p.Trigger.Owner, p.Trigger.Repo, p.Trigger.PRNumber, gitea.CreateReviewRequest{
					CommitID: p.Trigger.HeadSHA,
					Body:     args.Summary,
					Event:    verdict,
					Comments: comments,
				})
				if err != nil {
					return "", err
				}
			}
			reg.State.mu.Lock()
			reg.State.Submitted = true
			reg.State.mu.Unlock()
			return fmt.Sprintf("submitted review (%s) with %d inline comments", verdict, len(comments)), nil
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
			if p.Gitea != nil {
				if err := p.Gitea.PostComment(ctx, p.Trigger.Owner, p.Trigger.Repo, p.Trigger.PRNumber, args.Body); err != nil {
					return "", err
				}
			}
			reg.State.mu.Lock()
			reg.State.Submitted = true
			reg.State.Summary = args.Body
			reg.State.mu.Unlock()
			return "posted reply comment", nil
		},
	)

	if p.EnableWrite {
		reg.registerWriteTools(p)
	}

	return reg
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
			full, err := resolveWritablePath(p.WorktreeDir, args.Path)
			if err != nil {
				return "", err
			}
			if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
				return "", err
			}
			if err := os.WriteFile(full, []byte(args.Content), 0o644); err != nil {
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
			full, err := resolveWritablePath(p.WorktreeDir, args.Path)
			if err != nil {
				return "", err
			}
			rawBytes, err := os.ReadFile(full)
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
			if err := os.WriteFile(full, []byte(updated), 0o644); err != nil {
				return "", err
			}
			return fmt.Sprintf("edited %s", args.Path), nil
		},
	)

	r.register("commit_and_push",
		"Stage all changes in the PR worktree, commit them, and push to the PR head branch on Gitea.",
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
			newSHA, err := p.Workspace.CommitAndPush(ctx, p.WorktreeDir, p.Trigger.CloneURL, p.Trigger.HeadRef, p.AuthorName, args.Message)
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

// Execute runs a named tool and returns its output string.
func (r *Registry) Execute(ctx context.Context, name, rawArgs string) (string, error) {
	h, ok := r.handlers[name]
	if !ok {
		return "", fmt.Errorf("unknown tool: %s", name)
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
			if d.Name() == ".git" || d.Name() == "node_modules" || d.Name() == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		info, err := d.Info()
		if err != nil || info.Size() > 512*1024 {
			return nil
		}
		f, err := os.Open(path)
		if err != nil {
			return nil
		}
		defer f.Close()

		rel, _ := filepath.Rel(worktreeRoot, path)
		sc := bufio.NewScanner(f)
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
