package worker

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Eresus-Security-OSS/CodeSpider/internal/gitea"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/metrics"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/store"
)

type controlRecorder struct {
	mu       sync.Mutex
	comments []string
	resolved []string
	hits     []string
}

func (r *controlRecorder) add(s string) {
	r.mu.Lock()
	r.hits = append(r.hits, s)
	r.mu.Unlock()
}

func newControlServer(t *testing.T, rec *controlRecorder) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.add(r.Method + " " + r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/api/v1/repos/acme/api/collaborators/dev":
			w.WriteHeader(http.StatusNoContent)
		case r.URL.Path == "/api/v1/repos/acme/api/collaborators/stranger":
			w.WriteHeader(http.StatusNotFound)
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/comments") && strings.Contains(r.URL.Path, "/issues/"):
			var body struct {
				Body string `json:"body"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			rec.mu.Lock()
			rec.comments = append(rec.comments, body.Body)
			rec.mu.Unlock()
			w.WriteHeader(http.StatusCreated)
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/repos/acme/api/pulls/3/reviews":
			_ = json.NewEncoder(w).Encode([]gitea.PullReview{
				{ID: 7, User: gitea.User{Username: "codespider"}},
				{ID: 8, User: gitea.User{Username: "alice"}},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/repos/acme/api/pulls/3/reviews/7/comments":
			_ = json.NewEncoder(w).Encode([]gitea.PullReviewComment{
				{ID: 101, User: gitea.User{Username: "codespider"}},
				{ID: 102, User: gitea.User{Username: "codespider"}, Resolver: &gitea.User{ID: 9, Username: "dev"}},
				{ID: 103, User: gitea.User{Username: "alice"}},
			})
		case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/api/v1/repos/acme/api/pulls/comments/") && strings.HasSuffix(r.URL.Path, "/resolve"):
			rec.mu.Lock()
			rec.resolved = append(rec.resolved, r.URL.Path)
			rec.mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func newControlPool(t *testing.T, srvURL string) (*Pool, *store.Store) {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	pool := NewPool(Config{
		Workers:    1,
		QueueSize:  4,
		AuthorName: "codespider",
		Gitea:      gitea.NewClient(srvURL, "tok"),
		Store:      st,
		Metrics:    metrics.NewCollector(),
	})
	return pool, st
}

func controlTrigger(cmd, by string) gitea.ReviewTrigger {
	return gitea.ReviewTrigger{Kind: "comment_reply", Command: cmd, Owner: "acme", Repo: "api", PRNumber: 3, CommentBy: by}
}

func TestPauseRequiresCollaboratorAndSuppressesAutomaticReviews(t *testing.T) {
	rec := &controlRecorder{}
	srv := newControlServer(t, rec)
	pool, st := newControlPool(t, srv.URL)
	prKey := store.PRKey("acme", "api", 3)

	if _, err := pool.ExecuteSync(context.Background(), controlTrigger("pause", "stranger")); err == nil {
		t.Fatal("expected non-collaborator /pause to be refused")
	}
	if st.IsPaused(prKey) {
		t.Fatal("non-collaborator must not be able to pause a PR")
	}

	if _, err := pool.ExecuteSync(context.Background(), controlTrigger("pause", "dev")); err != nil {
		t.Fatalf("collaborator /pause failed: %v", err)
	}
	if !st.IsPaused(prKey) {
		t.Fatal("expected PR to be paused")
	}

	rec.mu.Lock()
	rec.hits = nil
	rec.mu.Unlock()
	auto := gitea.ReviewTrigger{Kind: "pr_review", Owner: "acme", Repo: "api", PRNumber: 3}
	if _, err := pool.ExecuteSync(context.Background(), auto); err != nil {
		t.Fatalf("paused automatic review should be a clean skip: %v", err)
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if len(rec.hits) != 0 {
		t.Fatalf("paused automatic review must not call Gitea, got %v", rec.hits)
	}
}

func TestResumeClearsPauseAndEnqueuesReview(t *testing.T) {
	rec := &controlRecorder{}
	srv := newControlServer(t, rec)
	pool, st := newControlPool(t, srv.URL)
	prKey := store.PRKey("acme", "api", 3)

	if _, err := st.SetPaused(prKey, true); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.ExecuteSync(context.Background(), controlTrigger("resume", "dev")); err != nil {
		t.Fatalf("/resume failed: %v", err)
	}
	if st.IsPaused(prKey) {
		t.Fatal("expected pause to be cleared")
	}
	select {
	case q := <-pool.queue:
		if q.Kind != "pr_review" || q.Command != "" || q.PRNumber != 3 {
			t.Fatalf("unexpected resume trigger: %+v", q)
		}
	case <-time.After(time.Second):
		t.Fatal("expected /resume to enqueue a review")
	}

	if _, err := pool.ExecuteSync(context.Background(), controlTrigger("resume", "dev")); err != nil {
		t.Fatal(err)
	}
	if pool.QueueDepth() != 0 {
		t.Fatal("/resume on an unpaused PR must not enqueue another review")
	}
}

func TestResolveOnlyTouchesOpenBotThreads(t *testing.T) {
	rec := &controlRecorder{}
	srv := newControlServer(t, rec)
	pool, _ := newControlPool(t, srv.URL)

	if _, err := pool.ExecuteSync(context.Background(), controlTrigger("resolve", "stranger")); err == nil {
		t.Fatal("expected non-collaborator /resolve to be refused")
	}
	rec.mu.Lock()
	if len(rec.resolved) != 0 {
		rec.mu.Unlock()
		t.Fatalf("refused /resolve must not resolve anything, got %v", rec.resolved)
	}
	rec.mu.Unlock()

	if _, err := pool.ExecuteSync(context.Background(), controlTrigger("resolve", "dev")); err != nil {
		t.Fatalf("/resolve failed: %v", err)
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if len(rec.resolved) != 1 || !strings.HasSuffix(rec.resolved[0], "/pulls/comments/101/resolve") {
		t.Fatalf("expected only bot comment 101 to be resolved, got %v", rec.resolved)
	}
	last := rec.comments[len(rec.comments)-1]
	if !strings.Contains(last, "Resolved 1 CodeSpider review thread") {
		t.Fatalf("unexpected confirmation comment: %q", last)
	}
	for _, h := range rec.hits {
		if strings.Contains(h, "/reviews/8/comments") {
			t.Fatal("must not scan reviews written by other users")
		}
	}
}

func TestResolveStopsEarlyWhenServerLacksEndpoint(t *testing.T) {
	var resolveCalls int
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.Contains(r.URL.Path, "/collaborators/"):
			w.WriteHeader(http.StatusNoContent)
		case strings.HasSuffix(r.URL.Path, "/reviews"):
			_ = json.NewEncoder(w).Encode([]gitea.PullReview{{ID: 7, User: gitea.User{Username: "codespider"}}})
		case strings.HasSuffix(r.URL.Path, "/reviews/7/comments"):
			var cs []gitea.PullReviewComment
			for i := range 10 {
				cs = append(cs, gitea.PullReviewComment{ID: int64(200 + i), User: gitea.User{Username: "codespider"}})
			}
			_ = json.NewEncoder(w).Encode(cs)
		case strings.HasSuffix(r.URL.Path, "/resolve"):
			mu.Lock()
			resolveCalls++
			mu.Unlock()
			http.NotFound(w, r)
		default:
			w.WriteHeader(http.StatusCreated)
		}
	}))
	defer srv.Close()
	pool, _ := newControlPool(t, srv.URL)

	if _, err := pool.ExecuteSync(context.Background(), controlTrigger("resolve", "dev")); err != nil {
		t.Fatalf("/resolve should report failures in a comment, not error: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if resolveCalls != maxResolveEarlyFailure {
		t.Fatalf("expected to stop after %d failed calls, made %d", maxResolveEarlyFailure, resolveCalls)
	}
}
