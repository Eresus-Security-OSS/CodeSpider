package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
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

func TestRunnerAutoSubmitsStagedCommentsOnBudgetExhaustion(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []any{map[string]any{
				"message": map[string]any{
					"role": "assistant",
					"tool_calls": []any{map[string]any{
						"id":   "call_1",
						"type": "function",
						"function": map[string]any{
							"name":      "add_inline_comment",
							"arguments": `{"path":"main.go","line":4,"severity":"critical","body":"SQL injection risk"}`,
						},
					}},
				},
			}},
			"usage": map[string]any{"total_tokens": 50},
		})
	}))
	defer srv.Close()

	llmClient := llm.NewClient(srv.URL, "k", "m", 5*time.Second)
	runner := NewRunner(llmClient, Options{MaxSteps: 1, MaxTokens: 5000})

	trigger := gitea.ReviewTrigger{Kind: "pr_review", Owner: "acme", Repo: "api", PRNumber: 2}
	reg := tools.NewRegistry(tools.Params{Trigger: trigger, Diff: "diff --git a/main.go b/main.go\n+db.Exec(q)"})

	res, err := runner.Run(context.Background(), trigger, reg)
	if err != nil {
		t.Fatalf("runner.Run failed: %v", err)
	}
	if !res.Submitted || res.InlineComments != 1 {
		t.Fatalf("expected auto-submit on budget exhaustion, got: %+v", res)
	}
}

func TestRunnerModelRoutingAndBlueTeamRefutation(t *testing.T) {
	var usedModels []string
	var turn atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Model string `json:"model"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		usedModels = append(usedModels, req.Model)

		n := turn.Add(1)
		w.Header().Set("Content-Type", "application/json")
		var resp map[string]any
		switch n {
		case 1:
			// Red-team/reviewer stages 2 findings and calls submit_review (deferred)
			resp = map[string]any{
				"choices": []any{map[string]any{
					"message": map[string]any{
						"role": "assistant",
						"tool_calls": []any{
							map[string]any{
								"id": "c1", "type": "function",
								"function": map[string]any{"name": "add_inline_comment", "arguments": `{"path":"main.go","line":10,"severity":"critical","body":"False positive SQLi"}`},
							},
							map[string]any{
								"id": "c2", "type": "function",
								"function": map[string]any{"name": "add_inline_comment", "arguments": `{"path":"main.go","line":20,"severity":"warning","body":"Real nil bug"}`},
							},
							map[string]any{
								"id": "c3", "type": "function",
								"function": map[string]any{"name": "submit_review", "arguments": `{"verdict":"COMMENT","summary":"Initial review"}`},
							},
						},
					},
				}},
				"usage": map[string]any{"total_tokens": 100},
			}
		case 2:
			// Blue-Team verifier refutes [0] and confirms [1]
			resp = map[string]any{
				"choices": []any{map[string]any{
					"message": map[string]any{
						"role": "assistant",
						"tool_calls": []any{
							map[string]any{
								"id": "b1", "type": "function",
								"function": map[string]any{"name": "record_verdict", "arguments": `{"index":0,"verdict":"REFUTE","reason":"Parameterized upstream"}`},
							},
							map[string]any{
								"id": "b2", "type": "function",
								"function": map[string]any{"name": "record_verdict", "arguments": `{"index":1,"verdict":"CONFIRM","reason":"Unchecked nil"}`},
							},
						},
					},
				}},
				"usage": map[string]any{"total_tokens": 80},
			}
		default:
			t.Fatalf("unexpected LLM turn %d", n)
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	llmClient := llm.NewClient(srv.URL, "k", "gpt-5", 5*time.Second)
	runner := NewRunner(llmClient, Options{
		MaxSteps:            5,
		MaxTokens:           5000,
		FastModel:           "gpt-5-mini",
		AdversarialSecurity: true,
	})

	trigger := gitea.ReviewTrigger{
		Kind:          "pr_review",
		Owner:         "acme",
		Repo:          "api",
		PRNumber:      9,
		DiffLineCount: 20, // small PR routes to FastModel
	}
	reg := tools.NewRegistry(tools.Params{Trigger: trigger, Diff: ""})

	res, err := runner.Run(context.Background(), trigger, reg)
	if err != nil {
		t.Fatalf("runner.Run failed: %v", err)
	}
	if res.ModelUsed != "gpt-5-mini" || len(usedModels) != 2 || usedModels[0] != "gpt-5-mini" {
		t.Fatalf("expected FastModel routing, got model=%q used=%v", res.ModelUsed, usedModels)
	}
	if !res.Submitted || res.InlineComments != 1 || res.BlueTeamRefuted != 1 {
		t.Fatalf("expected 1 confirmed and 1 refuted comment, got %+v", res)
	}
	if !strings.Contains(reg.State.SnapshotComments()[0].Body, "[MODEL CORROBORATED]") {
		t.Fatalf("expected corroborated badge on surviving comment, got: %s", reg.State.SnapshotComments()[0].Body)
	}
}
