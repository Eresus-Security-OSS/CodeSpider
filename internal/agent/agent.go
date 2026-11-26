// Package agent implements the autonomous tool-calling review loop with guardrails.
package agent

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/Eresus-Security-OSS/CodeSpider/internal/gitea"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/llm"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/skills"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/tools"
)

// Options controls agent execution budgets and active skills.
type Options struct {
	MaxSteps    int
	MaxTokens   int
	EnableWrite bool
	Skills      []skills.Skill
	Logger      *slog.Logger
}

// RunResult summarizes a completed agent run.
type RunResult struct {
	StepsUsed      int
	TokensUsed     int
	InlineComments int
	Submitted      bool
	FinalText      string
}

// Runner executes the tool-calling agent loop for a single PR trigger.
type Runner struct {
	llm  *llm.Client
	opts Options
}

// NewRunner creates an agent Runner.
func NewRunner(llmClient *llm.Client, opts Options) *Runner {
	if opts.MaxSteps <= 0 {
		opts.MaxSteps = 12
	}
	if opts.MaxTokens <= 0 {
		opts.MaxTokens = 32000
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	return &Runner{llm: llmClient, opts: opts}
}

// Run executes the agent loop until the agent submits a review/reply or hits a guardrail.
func (r *Runner) Run(ctx context.Context, trigger gitea.ReviewTrigger, reg *tools.Registry) (RunResult, error) {
	messages := []llm.Message{
		{Role: "system", Content: r.buildSystemPrompt(trigger)},
		{Role: "user", Content: buildUserPrompt(trigger)},
	}

	var res RunResult
	seenCalls := make(map[string]int)

	for step := 1; step <= r.opts.MaxSteps; step++ {
		if ctx.Err() != nil {
			return res, ctx.Err()
		}
		if res.TokensUsed >= r.opts.MaxTokens {
			r.opts.Logger.Warn("agent token budget reached", "tokens", res.TokensUsed, "pr", trigger.PRNumber)
			break
		}

		resp, err := r.llm.Chat(ctx, messages, reg.Definitions())
		if err != nil {
			return res, fmt.Errorf("step %d llm call: %w", step, err)
		}
		res.StepsUsed = step
		res.TokensUsed += resp.Usage.TotalTokens
		messages = append(messages, resp.Message)

		if len(resp.Message.ToolCalls) == 0 {
			res.FinalText = resp.Message.Content
			break
		}

		for _, tc := range resp.Message.ToolCalls {
			sig := tc.Function.Name + ":" + tc.Function.Arguments
			seenCalls[sig]++
			var obs string
			if seenCalls[sig] > 2 {
				obs = "error: repeated identical tool call detected; proceed to final review or try different arguments"
			} else {
				out, execErr := reg.Execute(ctx, tc.Function.Name, tc.Function.Arguments)
				if execErr != nil {
					obs = fmt.Sprintf("error: %v", execErr)
				} else {
					obs = out
				}
			}

			messages = append(messages, llm.Message{
				Role:       "tool",
				ToolCallID: tc.ID,
				Content:    obs,
			})
		}

		if reg.State.Submitted {
			break
		}
	}

	res.InlineComments = len(reg.State.InlineComments)
	res.Submitted = reg.State.Submitted
	return res, nil
}

func (r *Runner) buildSystemPrompt(trigger gitea.ReviewTrigger) string {
	var b strings.Builder
	b.WriteString(`You are CodeSpider, a 24/7 autonomous code review agent for Gitea.
Your job is to review pull requests accurately using the provided tools, without guessing or inventing code you did not read.

Workflow:
1. Inspect the PR diff using get_pr_diff.
2. When you need surrounding context, callers, or tests, use read_file or search_code on the PR worktree.
3. Focus on real bugs, security vulnerabilities, race conditions, resource leaks, and maintainability issues. Avoid nitpicking formatting.
4. For each concrete issue on a changed line, call add_inline_comment with exact file path and new line number.
5. Finish by calling submit_review (for PR reviews) or reply_comment (for @mention questions).
`)
	if skillSection := skills.FormatPrompt(r.opts.Skills); skillSection != "" {
		b.WriteString("\n")
		b.WriteString(skillSection)
	}
	if trigger.Kind == "comment_reply" {
		b.WriteString("\nThis run was triggered by a user @mention comment. Answer their question or request directly and finish with reply_comment.\n")
	}
	if r.opts.EnableWrite {
		b.WriteString("\nWrite mode is enabled: you have write_file, edit_file, and commit_and_push tools. Only modify files and push commits when explicitly asked to fix or implement changes (e.g. in an @mention request); for normal automatic PR reviews, only review without modifying code.\n")
	}
	return b.String()
}

func buildUserPrompt(t gitea.ReviewTrigger) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Repository: %s/%s\n", t.Owner, t.Repo)
	fmt.Fprintf(&b, "PR #%d: %s\n", t.PRNumber, t.PRTitle)
	if t.BaseRef != "" || t.HeadRef != "" {
		fmt.Fprintf(&b, "Branches: %s <- %s (head SHA: %s)\n", t.BaseRef, t.HeadRef, t.HeadSHA)
	}
	if strings.TrimSpace(t.PRBody) != "" {
		fmt.Fprintf(&b, "\nPR Description:\n%s\n", t.PRBody)
	}
	if t.Kind == "comment_reply" {
		fmt.Fprintf(&b, "\nComment from @%s:\n%s\n", t.CommentBy, t.Instruction)
	} else {
		b.WriteString("\nPlease review this pull request now.")
	}
	return b.String()
}
