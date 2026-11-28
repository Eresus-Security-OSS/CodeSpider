package gitea

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestParseBotCommandControlCommandsNeedSlashForm(t *testing.T) {
	for cmd, want := range map[string]string{"/pause": "pause", "/resume": "resume", "/resolve": "resolve"} {
		kind, command, _ := ParseBotCommand("@codespider "+cmd, "codespider")
		if kind != "comment_reply" || command != want {
			t.Errorf("%s: got kind=%q command=%q", cmd, kind, command)
		}
	}
	for _, body := range []string{"@codespider pause", "@codespider resume the work please", "@codespider resolve this how?"} {
		if _, command, _ := ParseBotCommand(body, "codespider"); command != "ask" {
			t.Errorf("%q must stay a question, got command %q", body, command)
		}
	}
}

func TestReviewThreadClientCalls(t *testing.T) {
	var resolvePath, resolveMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/repos/acme/api/pulls/3/reviews/7/comments":
			_ = json.NewEncoder(w).Encode([]map[string]any{
				{"id": 1, "user": map[string]any{"username": "codespider"}, "resolver": nil},
				{"id": 2, "user": map[string]any{"username": "codespider"}, "resolver": map[string]any{"id": 5, "username": "dev"}},
			})
		case "/api/v1/repos/acme/api/pulls/comments/1/resolve":
			resolvePath, resolveMethod = r.URL.Path, r.Method
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	c := NewClient(srv.URL, "tok")
	ctx := context.Background()

	comments, err := c.ListPullReviewComments(ctx, "acme", "api", 3, 7)
	if err != nil || len(comments) != 2 {
		t.Fatalf("ListPullReviewComments: %+v, %v", comments, err)
	}
	if comments[0].Resolved() || !comments[1].Resolved() {
		t.Fatalf("Resolved() mismatch: %+v", comments)
	}
	if err := c.ResolveReviewComment(ctx, "acme", "api", 1); err != nil {
		t.Fatalf("ResolveReviewComment: %v", err)
	}
	if resolveMethod != http.MethodPost || resolvePath == "" {
		t.Fatalf("expected POST to the resolve endpoint, got %s %s", resolveMethod, resolvePath)
	}
	if err := c.ResolveReviewComment(ctx, "acme", "api", 999); err == nil {
		t.Fatal("expected 404 from an unsupported server to surface as an error")
	}
}

func TestListPullReviewsFollowsPagination(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		var page []PullReview
		switch r.URL.Query().Get("page") {
		case "1":
			for i := range 50 {
				page = append(page, PullReview{ID: int64(i + 1)})
			}
		case "2":
			page = []PullReview{{ID: 51}}
		}
		_ = json.NewEncoder(w).Encode(page)
	}))
	defer srv.Close()

	got, err := NewClient(srv.URL, "tok").ListPullReviews(context.Background(), "acme", "api", 3)
	if err != nil || len(got) != 51 {
		t.Fatalf("expected 51 reviews across two pages, got %d, err=%v", len(got), err)
	}
}
