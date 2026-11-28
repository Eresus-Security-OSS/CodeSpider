package worker

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/Eresus-Security-OSS/CodeSpider/internal/agent"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/gitea"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/policy"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/repoconfig"
)

func TestAutoLabelReplacesOutdatedSizeLabel(t *testing.T) {
	var mu sync.Mutex
	var attached, deleted []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/repos/acme/api/labels":
			_, _ = w.Write([]byte(`[{"id":1,"name":"size/XS"},{"id":2,"name":"size/S"}]`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/repos/acme/api/issues/1/labels":
			mu.Lock()
			attached = append(attached, "post")
			mu.Unlock()
			_, _ = w.Write([]byte(`[]`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/repos/acme/api/issues/1/labels":
			_, _ = w.Write([]byte(`[{"id":1,"name":"size/XS"},{"id":2,"name":"size/S"},{"id":3,"name":"bug"}]`))
		case r.Method == http.MethodDelete:
			mu.Lock()
			deleted = append(deleted, r.URL.Path)
			mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		default:
			_, _ = w.Write([]byte(`[]`))
		}
	}))
	defer srv.Close()

	pool := NewPool(Config{Gitea: gitea.NewClient(srv.URL, "tok")})
	perms := policy.EvaluatePermissions(policy.Input{Owner: "acme", IsCollaborator: true})
	trigger := gitea.ReviewTrigger{Kind: "pr_review", Owner: "acme", Repo: "api", PRNumber: 1, HeadSHA: "abc12345"}

	// 30 added lines fall in the size/S bucket; the PR previously carried size/XS.
	diff := "diff --git a/a.go b/a.go\n--- a/a.go\n+++ b/a.go\n@@ -0,0 +1,30 @@\n" + strings.Repeat("+x\n", 30)
	pool.runPostReviewAutomations(context.Background(), trigger, perms, repoconfig.Config{AutoLabel: true}, diff, "", "alice", agent.RunResult{}, nil)

	mu.Lock()
	defer mu.Unlock()
	if len(attached) != 1 {
		t.Fatalf("expected the current labels to be attached once, got %d", len(attached))
	}
	if len(deleted) != 1 || deleted[0] != "/api/v1/repos/acme/api/issues/1/labels/1" {
		t.Fatalf("expected only the stale size/XS label (id 1) to be removed, got %v", deleted)
	}
}
