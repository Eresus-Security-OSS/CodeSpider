package worker

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Eresus-Security-OSS/CodeSpider/internal/agent"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/gitea"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/llm"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/metrics"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/store"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/workspace"
)

func TestSupersedingClearActiveDoesNotDeleteNewerJob(t *testing.T) {
	pool := NewPool(Config{})
	prKey := "acme/api#1"

	_, cancel1 := context.WithCancel(context.Background())
	defer cancel1()
	id1 := pool.registerActive(prKey, cancel1)

	_, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	id2 := pool.registerActive(prKey, cancel2)

	// Clearing id1 must NOT remove id2 from active map
	pool.clearActive(prKey, id1)
	if !pool.IsActive(prKey) {
		t.Fatal("expected newer job id2 to remain active after clearing id1")
	}

	pool.clearActive(prKey, id2)
	if pool.IsActive(prKey) {
		t.Fatal("expected job to be cleared when matching id2 is passed")
	}
}

func TestWorkerHelpCommandAndReconcileOnce(t *testing.T) {
	var postedHelp atomic.Bool
	giteaSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/repos/acme/api/issues/comments/55/reactions":
			w.WriteHeader(http.StatusCreated)
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/repos/acme/api/issues/3/comments":
			postedHelp.Store(true)
			w.WriteHeader(http.StatusCreated)
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/repos/acme/api/pulls":
			_ = json.NewEncoder(w).Encode([]gitea.PullRequest{
				{
					Number: 10,
					Title:  "Unreviewed PR",
					Head:   gitea.BranchRef{Ref: "feat", SHA: "deadbeef"},
					Base:   gitea.BranchRef{Ref: "main", Repo: gitea.Repository{CloneURL: "https://gitea.local/acme/api.git"}},
					User:   gitea.User{Username: "alice"},
				},
				{
					Number: 11,
					Title:  "Draft PR",
					Draft:  true,
					Head:   gitea.BranchRef{Ref: "wip", SHA: "1234567"},
					User:   gitea.User{Username: "alice"},
				},
				{
					Number: 12,
					Title:  "Already Reviewed PR",
					Head:   gitea.BranchRef{Ref: "done", SHA: "reviewedsha"},
					User:   gitea.User{Username: "alice"},
				},
			})
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer giteaSrv.Close()

	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := st.RecordRun(store.RunRecord{
		PRKey:      store.PRKey("acme", "api", 12),
		Kind:       "pr_review",
		HeadSHA:    "reviewedsha",
		Status:     "success",
		FinishedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}

	mc := metrics.NewCollector()
	pool := NewPool(Config{
		Workers:    1,
		QueueSize:  16,
		AuthorName: "codespider",
		SkipDrafts: true,
		IgnoreBots: true,
		Gitea:      gitea.NewClient(giteaSrv.URL, "tok"),
		Workspace:  workspace.NewManager(t.TempDir(), "tok"),
		Agent:      agent.NewRunner(llm.NewClient("http://127.0.0.1:0", "k", "m", time.Second), agent.Options{}),
		Store:      st,
		Metrics:    mc,
	})

	// Test /help fast-path directly
	pool.handleTrigger(context.Background(), 1, gitea.ReviewTrigger{
		Kind:      "comment_reply",
		Command:   "help",
		Owner:     "acme",
		Repo:      "api",
		PRNumber:  3,
		CommentID: 55,
	})
	if !postedHelp.Load() {
		t.Fatal("expected /help command to post help comment")
	}

	// Test ReconcileOnce enqueues only PR #10 (skips draft #11 and reviewed #12)
	enqueued := pool.ReconcileOnce(context.Background(), []string{"acme/api"})
	if enqueued != 1 {
		t.Fatalf("expected 1 enqueued PR, got %d", enqueued)
	}
	if pool.QueueDepth() != 1 {
		t.Fatalf("expected QueueDepth 1, got %d", pool.QueueDepth())
	}
	tr := <-pool.queue
	if tr.PRNumber != 10 || !strings.EqualFold(tr.HeadSHA, "deadbeef") {
		t.Fatalf("unexpected reconciled trigger: %+v", tr)
	}
}

func TestWorkerCollaboratorGateForFixAndExecuteSyncDryRun(t *testing.T) {
	var postedUnauthorized atomic.Bool
	var alertSent atomic.Bool

	alertSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		alertSent.Store(true)
		w.WriteHeader(http.StatusOK)
	}))
	defer alertSrv.Close()

	giteaSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/repos/acme/api/collaborators/outsider":
			w.WriteHeader(http.StatusNotFound)
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/repos/acme/api/issues/4/comments":
			postedUnauthorized.Store(true)
			w.WriteHeader(http.StatusCreated)
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/repos/acme/api/pulls/7":
			_ = json.NewEncoder(w).Encode(gitea.PullRequest{
				Number: 7,
				Title:  "Dry run PR",
				Head:   gitea.BranchRef{Ref: "feat", SHA: "deadbeef"},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/repos/acme/api/pulls/7.diff":
			_, _ = w.Write([]byte("diff --git a/main.go b/main.go\n+++ b/main.go\n@@ -1,1 +1,2 @@\n+const k = \"AKIAZ9X8C7V6B5N4M3Q2\"\n"))
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/repos/acme/api/collaborators/outsider":
			w.WriteHeader(http.StatusNotFound)
		default:
			t.Fatalf("unexpected Gitea call in dry-run/gate test: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer giteaSrv.Close()

	llmSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []any{map[string]any{
				"message": map[string]any{
					"role": "assistant",
					"tool_calls": []any{map[string]any{
						"id": "call_1", "type": "function",
						"function": map[string]any{
							"name":      "submit_review",
							"arguments": `{"verdict":"REQUEST_CHANGES","summary":"Found secret"}`,
						},
					}},
				},
			}},
			"usage": map[string]any{"total_tokens": 25},
		})
	}))
	defer llmSrv.Close()

	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	pool := NewPool(Config{
		Workers:                   1,
		AuthorName:                "codespider",
		RequireCollaboratorForFix: true,
		AlertWebhookURL:           alertSrv.URL,
		Gitea:                     gitea.NewClient(giteaSrv.URL, "tok"),
		Agent:                     agent.NewRunner(llm.NewClient(llmSrv.URL, "k", "gpt-5", 2*time.Second), agent.Options{}),
		Store:                     st,
		Metrics:                   metrics.NewCollector(),
	})

	// Unauthorized /fix should be rejected before touching LLM
	_, err = pool.ExecuteSync(context.Background(), gitea.ReviewTrigger{
		Kind:      "comment_reply",
		Command:   "fix",
		Owner:     "acme",
		Repo:      "api",
		PRNumber:  4,
		CommentBy: "outsider",
	})
	if err == nil || !postedUnauthorized.Load() {
		t.Fatalf("expected unauthorized /fix rejection, err=%v posted=%v", err, postedUnauthorized.Load())
	}

	// DryRun review should return findings and secret alerts without mutating Gitea or alert webhook
	dryRes, err := pool.ExecuteSync(context.Background(), gitea.ReviewTrigger{
		Kind:     "pr_review",
		DryRun:   true,
		Owner:    "acme",
		Repo:     "api",
		PRNumber: 7,
	})
	if err != nil {
		t.Fatalf("ExecuteSync dry-run failed: %v", err)
	}
	if len(dryRes.SecretFindings) != 1 || dryRes.Verdict != "REQUEST_CHANGES" {
		t.Fatalf("unexpected dry-run result: %+v", dryRes)
	}
	if alertSent.Load() {
		t.Fatal("dry-run must not trigger alert webhook")
	}
}

func TestReconcileOnceMarksForkPRs(t *testing.T) {
	giteaSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]gitea.PullRequest{
			{
				Number: 10,
				Title:  "Fork PR",
				User:   gitea.User{Username: "outsider"},
				Base:   gitea.BranchRef{Ref: "main", Repo: gitea.Repository{ID: 1, FullName: "acme/api", CloneURL: "https://gitea.local/acme/api.git"}},
				Head:   gitea.BranchRef{Ref: "patch-1", SHA: "1111111", Repo: gitea.Repository{ID: 2, FullName: "outsider/api"}},
			},
			{
				Number: 11,
				Title:  "Internal PR",
				User:   gitea.User{Username: "alice"},
				Base:   gitea.BranchRef{Ref: "main", Repo: gitea.Repository{ID: 1, FullName: "acme/api", CloneURL: "https://gitea.local/acme/api.git"}},
				Head:   gitea.BranchRef{Ref: "feat", SHA: "2222222", Repo: gitea.Repository{ID: 1, FullName: "acme/api"}},
			},
		})
	}))
	defer giteaSrv.Close()

	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	pool := NewPool(Config{
		Workers: 1,
		Gitea:   gitea.NewClient(giteaSrv.URL, "tok"),
		Store:   st,
		Metrics: metrics.NewCollector(),
	})

	if n := pool.ReconcileOnce(context.Background(), []string{"acme/api"}); n != 2 {
		t.Fatalf("expected 2 enqueued PRs, got %d", n)
	}
	t1 := <-pool.queue
	t2 := <-pool.queue
	if t1.PRNumber != 10 || !t1.IsFork {
		t.Fatalf("expected PR #10 from fork to have IsFork=true, got %+v", t1)
	}
	if t2.PRNumber != 11 || t2.IsFork {
		t.Fatalf("expected PR #11 from same repo to have IsFork=false, got %+v", t2)
	}
}
