package gitea

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestClientEndpoints(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if got := r.Header.Get("Authorization"); got != "token test-tok" {
			t.Fatalf("unexpected auth header: %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/repos/acme/api/pulls/1":
			_ = json.NewEncoder(w).Encode(PullRequest{Number: 1, Title: "Test PR"})
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/repos/acme/api/pulls":
			_ = json.NewEncoder(w).Encode([]PullRequest{{Number: 1, Title: "Test PR"}})
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/repos/acme/api/pulls/1/reviews":
			_ = json.NewEncoder(w).Encode([]PullReview{{ID: 10, State: "COMMENT", CommitID: "abc"}})
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/user/repos":
			_ = json.NewEncoder(w).Encode([]Repository{{FullName: "acme/api", CloneURL: "https://gitea.local/acme/api.git"}})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/repos/acme/api/issues/1/reactions":
			w.WriteHeader(http.StatusCreated)
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/repos/acme/api/issues/comments/99/reactions":
			w.WriteHeader(http.StatusCreated)
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/repos/acme/api/pulls/1/reviews":
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/repos/acme/api/statuses/abc":
			w.WriteHeader(http.StatusCreated)
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/repos/acme/api/issues/1/comments":
			_ = json.NewEncoder(w).Encode([]Comment{{ID: 5, Body: "<!-- marker -->\nold"}})
		case r.Method == http.MethodPatch && r.URL.Path == "/api/v1/repos/acme/api/issues/comments/5":
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/repos/acme/api/collaborators/alice":
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/repos/acme/api/labels":
			_ = json.NewEncoder(w).Encode([]Label{{ID: 1, Name: "security", Color: "#d73a4a"}})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/repos/acme/api/issues/1/labels":
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/repos/acme/api/pulls/1/requested_reviewers":
			w.WriteHeader(http.StatusCreated)
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/repos/acme/api/commits/abc/status":
			_ = json.NewEncoder(w).Encode(CombinedStatus{State: "failure"})
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer srv.Close()

	ctx := context.Background()
	c := NewClient(srv.URL, "test-tok")

	pr, err := c.GetPullRequest(ctx, "acme", "api", 1)
	if err != nil || pr.Number != 1 {
		t.Fatalf("GetPullRequest failed: %+v, err=%v", pr, err)
	}
	prs, err := c.ListOpenPullRequests(ctx, "acme", "api")
	if err != nil || len(prs) != 1 {
		t.Fatalf("ListOpenPullRequests failed: %+v, err=%v", prs, err)
	}
	revs, err := c.ListPullReviews(ctx, "acme", "api", 1)
	if err != nil || len(revs) != 1 || revs[0].CommitID != "abc" {
		t.Fatalf("ListPullReviews failed: %+v, err=%v", revs, err)
	}
	repos, err := c.ListAccessibleRepos(ctx)
	if err != nil || len(repos) != 1 || repos[0].FullName != "acme/api" {
		t.Fatalf("ListAccessibleRepos failed: %+v, err=%v", repos, err)
	}
	if err := c.AddIssueReaction(ctx, "acme", "api", 1, "eyes"); err != nil {
		t.Fatalf("AddIssueReaction failed: %v", err)
	}
	if err := c.AddCommentReaction(ctx, "acme", "api", 99, "eyes"); err != nil {
		t.Fatalf("AddCommentReaction failed: %v", err)
	}
	if err := c.CreateReview(ctx, "acme", "api", 1, CreateReviewRequest{Body: "LGTM"}); err != nil {
		t.Fatalf("CreateReview failed: %v", err)
	}
	if err := c.SetCommitStatus(ctx, "acme", "api", "abc", "success", "ok"); err != nil {
		t.Fatalf("SetCommitStatus failed: %v", err)
	}
	if err := c.UpsertStickyComment(ctx, "acme", "api", 1, "<!-- marker -->", "new body"); err != nil {
		t.Fatalf("UpsertStickyComment failed: %v", err)
	}
	isCollab, err := c.IsCollaborator(ctx, "acme", "api", "alice")
	if err != nil || !isCollab {
		t.Fatalf("IsCollaborator failed: %v, %v", isCollab, err)
	}
	if err := c.EnsureAndAddLabels(ctx, "acme", "api", 1, []string{"security"}); err != nil {
		t.Fatalf("EnsureAndAddLabels failed: %v", err)
	}
	if err := c.RequestReviewers(ctx, "acme", "api", 1, []string{"bob"}); err != nil {
		t.Fatalf("RequestReviewers failed: %v", err)
	}
	cs, err := c.GetCombinedCommitStatus(ctx, "acme", "api", "abc")
	if err != nil || cs.State != "failure" {
		t.Fatalf("GetCombinedCommitStatus failed: %+v, %v", cs, err)
	}
	if hits.Load() != 15 {
		t.Fatalf("expected 15 HTTP calls, got %d", hits.Load())
	}
}

func TestUpsertStickyCommentReturnsListErrorWithoutDuplicatePost(t *testing.T) {
	var postHits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			postHits.Add(1)
		}
		http.Error(w, "bad gateway", http.StatusBadGateway)
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "test-tok")
	err := c.UpsertStickyComment(context.Background(), "acme", "api", 1, "<!-- marker -->", "body")
	if err == nil {
		t.Fatal("expected error when listing PR comments fails")
	}
	if postHits.Load() != 0 {
		t.Fatalf("expected no duplicate POST comment on list failure, got %d", postHits.Load())
	}
}
