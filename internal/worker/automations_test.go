package worker

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/Eresus-Security-OSS/CodeSpider/internal/agent"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/gitea"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/policy"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/repoconfig"
)

func TestRunPostReviewAutomationsConcurrentConfigReload(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte("[]"))
			return
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	pool := NewPool(Config{
		StickySummary:   true,
		AlertWebhookURL: srv.URL,
		Gitea:           gitea.NewClient(srv.URL, "tok"),
	})

	perms := policy.EvaluatePermissions(policy.Input{
		Owner:          "acme",
		IsCollaborator: true,
	})
	trigger := gitea.ReviewTrigger{
		Kind:     "pr_review",
		Owner:    "acme",
		Repo:     "api",
		PRNumber: 1,
		HeadSHA:  "abc12345",
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			pool.UpdateRuntimeConfig(i%2 == 0, srv.URL, false, nil)
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 20; i++ {
			pool.runPostReviewAutomations(
				context.Background(),
				trigger,
				perms,
				repoconfig.Config{},
				"",
				"",
				"alice",
				agent.RunResult{HasCritical: true, Summary: "ok"},
				nil,
			)
		}
	}()
	wg.Wait()
}
