package github

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Eresus-Security-OSS/CodeSpider/internal/gitea"
)

func TestClientPullRequestAndDiff(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("authorization = %q", r.Header.Get("Authorization"))
		}
		switch {
		case r.URL.Path == "/repos/acme/widget/pulls/7" && r.Header.Get("Accept") == "application/vnd.github+json":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"number":7,"title":"change","draft":true,"head":{"ref":"feature","sha":"abc","repo":{"full_name":"acme/widget","clone_url":"https://github.com/acme/widget.git"}},"base":{"ref":"main","sha":"def"},"user":{"login":"alice"}}`))
		case r.URL.Path == "/repos/acme/widget/pulls/7" && r.Header.Get("Accept") == "application/vnd.github.diff":
			_, _ = w.Write([]byte("diff --git a/a.go b/a.go\n"))
		default:
			t.Errorf("unexpected request: %s %s accept=%s", r.Method, r.URL.Path, r.Header.Get("Accept"))
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client := NewClient(server.URL, "test-token")
	pr, err := client.GetPullRequest(context.Background(), "acme", "widget", 7)
	if err != nil {
		t.Fatal(err)
	}
	if pr.Number != 7 || !pr.Draft || pr.Head.SHA != "abc" || pr.User.Login != "alice" {
		t.Fatalf("unexpected PR mapping: %+v", pr)
	}
	diff, err := client.GetPullRequestDiff(context.Background(), "acme", "widget", 7)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(diff, "diff --git") {
		t.Fatalf("unexpected diff: %q", diff)
	}
}

func TestClientSubmitsReviewAndAddsLabelsWithoutReplacingExisting(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/repos/acme/widget/labels"):
			_, _ = w.Write([]byte(`[]`))
		case r.Method == http.MethodPost && r.URL.Path == "/repos/acme/widget/labels":
			w.WriteHeader(http.StatusCreated)
		case r.Method == http.MethodPost && r.URL.Path == "/repos/acme/widget/issues/7/labels":
			var body struct {
				Labels []string `json:"labels"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Error(err)
			}
			if len(body.Labels) != 1 || body.Labels[0] != "security" {
				t.Errorf("unexpected label add: %#v", body.Labels)
			}
		case r.Method == http.MethodPost && r.URL.Path == "/repos/acme/widget/pulls/7/reviews":
			var body struct {
				Comments []struct {
					Line int64  `json:"line"`
					Side string `json:"side"`
				} `json:"comments"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Error(err)
			}
			if len(body.Comments) != 1 || body.Comments[0].Line != 12 || body.Comments[0].Side != "RIGHT" {
				t.Errorf("unexpected review comment: %+v", body.Comments)
			}
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodPost && r.URL.Path == "/repos/acme/widget/pulls/comments/22/reactions":
			var body struct {
				Content string `json:"content"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Error(err)
			}
			if body.Content != "eyes" {
				t.Errorf("reaction content = %q", body.Content)
			}
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.String())
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client := NewClient(server.URL, "token")
	if err := client.EnsureAndAddLabels(context.Background(), "acme", "widget", 7, []string{"security"}); err != nil {
		t.Fatal(err)
	}
	if err := client.SubmitReview(context.Background(), "acme", "widget", 7, gitea.CreateReviewRequest{Event: "COMMENT", Body: "summary", Comments: []gitea.ReviewComment{{Path: "main.go", NewLineNum: 12, Body: "check this"}}}); err != nil {
		t.Fatal(err)
	}
	if err := client.AddReviewCommentReaction(context.Background(), "acme", "widget", 22, "eyes"); err != nil {
		t.Fatal(err)
	}
}

func TestGitHubReviewThreadResolutionUsesGraphQL(t *testing.T) {
	var resolved string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/graphql" {
			t.Errorf("unexpected endpoint %s", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		var request struct {
			Query     string         `json:"query"`
			Variables map[string]any `json:"variables"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Error(err)
		}
		if strings.Contains(request.Query, "resolveReviewThread") {
			resolved, _ = request.Variables["threadId"].(string)
			_, _ = w.Write([]byte(`{"data":{"resolveReviewThread":{"thread":{"id":"PRRT_thread","isResolved":true}}}}`))
			return
		}
		_, _ = w.Write([]byte(`{"data":{"repository":{"pullRequest":{"reviewThreads":{"nodes":[{"id":"PRRT_thread","isResolved":false,"comments":{"nodes":[{"fullDatabaseId":"42","author":{"login":"codespider[bot]"},"pullRequestReview":{"fullDatabaseId":"7"}}]}}],"pageInfo":{"hasNextPage":false,"endCursor":null}}}}}}`))
	}))
	defer server.Close()
	client := NewClient(server.URL, "token")
	comments, err := client.ListPullReviewComments(context.Background(), "acme", "api", 8, 7)
	if err != nil {
		t.Fatal(err)
	}
	if len(comments) != 1 || comments[0].ID != 42 || comments[0].User.Login != "codespider[bot]" || comments[0].Resolved() {
		t.Fatalf("unexpected comments: %+v", comments)
	}
	if err := client.ResolveReviewComment(context.Background(), "acme", "api", 42); err != nil {
		t.Fatal(err)
	}
	if resolved != "PRRT_thread" {
		t.Fatalf("resolved thread id=%q", resolved)
	}
}

func TestInstallationTokenListsInstallationRepositories(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/installation/repositories" {
			t.Errorf("installation token used wrong repository endpoint: %s", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"repositories":[{"id":1,"full_name":"acme/api","clone_url":"https://github.com/acme/api.git"}]}`))
	}))
	defer server.Close()
	client := NewClientWithTokenSource(server.URL, staticTestToken("app-token"))
	repos, err := client.ListAccessibleRepos(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(repos) != 1 || repos[0].FullName != "acme/api" {
		t.Fatalf("unexpected installation repos: %+v", repos)
	}
}

type staticTestToken string

func (s staticTestToken) Token(context.Context) (string, error) { return string(s), nil }
