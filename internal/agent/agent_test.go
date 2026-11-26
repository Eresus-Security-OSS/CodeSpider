package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Eresus-Security-OSS/CodeSpider/internal/gitea"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/llm"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/tools"
)

func TestRunnerExecutesToolLoopAndSubmitsReview(t *testing.T) {
	var turn atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := turn.Add(1)
		w.Header().Set("Content-Type", "application/json")
		var resp map[string]any
		switch n {
		case 1:
			resp = map[string]any{
				"choices": []any{map[string]any{
					"message": map[string]any{
						"role": "assistant",
						"tool_calls": []any{map[string]any{
							"id":   "call_1",
							"type": "function",
							"function": map[string]any{
								"name":      "get_pr_diff",
								"arguments": `{}`,
							},
						}},
					},
				}},
				"usage": map[string]any{"total_tokens": 100},
			}
		case 2:
			resp = map[string]any{
				"choices": []any{map[string]any{
					"message": map[string]any{
						"role": "assistant",
						"tool_calls": []any{
							map[string]any{
								"id":   "call_2",
								"type": "function",
								"function": map[string]any{
									"name":      "add_inline_comment",
									"arguments": `{"path":"main.go","line":10,"severity":"warning","body":"Check error return"}`,
								},
							},
							map[string]any{
								"id":   "call_3",
								"type": "function",
								"function": map[string]any{
									"name":      "submit_review",
									"arguments": `{"verdict":"COMMENT","summary":"Looks mostly good, 1 warning."}`,
								},
							},
						},
					},
				}},
				"usage": map[string]any{"total_tokens": 150},
			}
		default:
			t.Fatalf("unexpected extra LLM turn %d", n)
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	llmClient := llm.NewClient(srv.URL, "test-key", "test-model", 5*time.Second)
	runner := NewRunner(llmClient, Options{MaxSteps: 5, MaxTokens: 5000})

	trigger := gitea.ReviewTrigger{
		Kind:     "pr_review",
		Owner:    "acme",
		Repo:     "api",
		PRNumber: 1,
		PRTitle:  "Test PR",
	}
	reg := tools.NewRegistry(tools.Params{
		Trigger: trigger,
		Diff:    "diff --git a/main.go b/main.go\n+fmt.Println(\"hi\")",
	})

	res, err := runner.Run(context.Background(), trigger, reg)
	if err != nil {
		t.Fatalf("runner.Run failed: %v", err)
	}
	if !res.Submitted || res.InlineComments != 1 || res.StepsUsed != 2 || res.TokensUsed != 250 {
		t.Fatalf("unexpected run result: %+v", res)
	}
}
