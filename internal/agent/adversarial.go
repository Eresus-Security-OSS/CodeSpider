package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Eresus-Security-OSS/CodeSpider/internal/events"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/gitea"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/llm"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/tools"
)

// runBlueTeamVerification runs a focused adversarial defender pass over staged inline comments.
// It inspects surrounding code and refutes false positives mitigated by upstream checks/middleware.
func (r *Runner) runBlueTeamVerification(
	ctx context.Context,
	client *llm.Client,
	trigger gitea.ReviewTrigger,
	reg *tools.Registry,
	broker *events.Broker,
) (tokensUsed int, refutedCount int) {
	staged := reg.State.SnapshotComments()
	if len(staged) == 0 {
		return 0, 0
	}

	prKey := fmt.Sprintf("%s/%s#%d", trigger.Owner, trigger.Repo, trigger.PRNumber)
	broker.Publish(events.Event{
		PRKey:   prKey,
		Type:    "blue_team",
		Message: fmt.Sprintf("Verifying %d staged finding(s) against codebase mitigations", len(staged)),
	})

	var findingsPrompt strings.Builder
	for i, c := range staged {
		fmt.Fprintf(&findingsPrompt, "[%d] %s:%d -> %s\n", i, c.Path, c.NewLineNum, c.Body)
	}

	verdicts := make(map[int]string)
	blueDefs := filterReadOnlyToolDefs(reg.Definitions())
	blueDefs = append(blueDefs, llm.ToolDefinition{
		Type: "function",
		Function: llm.FunctionDefinition{
			Name:        "record_verdict",
			Description: "Confirm or refute a staged finding index after checking codebase context.",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"index":   map[string]any{"type": "integer", "description": "0-based finding index"},
					"verdict": map[string]any{"type": "string", "description": "CONFIRM or REFUTE"},
					"reason":  map[string]any{"type": "string", "description": "Brief evidence-based justification"},
				},
				"required": []string{"index", "verdict", "reason"},
			},
		},
	})

	messages := []llm.Message{
		{
			Role: "system",
			Content: `You are CodeSpider Blue-Team Verifier.
Your job is to eliminate false positives from staged PR review findings.
For each staged finding:
1. Check callers, validators, middleware, or error handling using read_file / search_code / get_pr_diff if needed.
2. Call record_verdict for each index:
   - REFUTE if upstream validation, parameterization, auth, or tests already mitigate the issue.
   - CONFIRM if the vulnerability or bug is genuinely unmitigated.`,
		},
		{
			Role:    "user",
			Content: fmt.Sprintf("PR %s\n\nStaged findings to verify:\n%s", prKey, findingsPrompt.String()),
		},
	}

	const maxVerifySteps = 4
	for step := 1; step <= maxVerifySteps; step++ {
		if ctx.Err() != nil {
			break
		}
		resp, err := client.Chat(ctx, messages, blueDefs)
		if err != nil {
			break
		}
		tokensUsed += resp.Usage.TotalTokens
		messages = append(messages, resp.Message)
		if len(resp.Message.ToolCalls) == 0 {
			break
		}
		for _, tc := range resp.Message.ToolCalls {
			var obs string
			if tc.Function.Name == "record_verdict" {
				var args struct {
					Index   int    `json:"index"`
					Verdict string `json:"verdict"`
					Reason  string `json:"reason"`
				}
				if err := json.Unmarshal([]byte(tc.Function.Arguments), &args); err != nil {
					obs = fmt.Sprintf("error: %v", err)
				} else {
					v := strings.ToUpper(strings.TrimSpace(args.Verdict))
					if v != "REFUTE" {
						v = "CONFIRM"
					}
					verdicts[args.Index] = v
					obs = fmt.Sprintf("recorded %s for [%d]", v, args.Index)
				}
			} else if !blueTeamReadOnlyTools[tc.Function.Name] {
				obs = fmt.Sprintf("error: tool %q is not permitted during Blue-Team verification", tc.Function.Name)
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
		if len(verdicts) >= len(staged) {
			break
		}
	}

	var confirmed, refuted []int
	for i := range staged {
		switch verdicts[i] {
		case "REFUTE":
			refuted = append(refuted, i)
		case "CONFIRM":
			confirmed = append(confirmed, i)
		}
	}
	reg.State.MarkCorroborated(confirmed)
	reg.State.RemoveCommentsByIndices(refuted)

	if len(refuted) > 0 {
		broker.Publish(events.Event{
			PRKey:   prKey,
			Type:    "blue_team",
			Message: fmt.Sprintf("Refuted %d false-positive finding(s); confirmed %d", len(refuted), len(confirmed)),
		})
	}
	return tokensUsed, len(refuted)
}

var blueTeamReadOnlyTools = map[string]bool{
	"get_pr_diff":          true,
	"get_incremental_diff": true,
	"read_file":            true,
	"search_code":          true,
	"list_files":           true,
	"inspect_go_symbols":   true,
}

func filterReadOnlyToolDefs(defs []llm.ToolDefinition) []llm.ToolDefinition {
	var out []llm.ToolDefinition
	for _, d := range defs {
		if blueTeamReadOnlyTools[d.Function.Name] {
			out = append(out, d)
		}
	}
	return out
}
