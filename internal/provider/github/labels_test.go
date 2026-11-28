package github

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

func TestRemoveLabelsWithPrefixEscapesSlashAndIgnoresMissing(t *testing.T) {
	var mu sync.Mutex
	var deleted []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/repos/acme/widget/issues/4/labels":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[{"name":"size/XS"},{"name":"size/S"},{"name":"bug"}]`))
		case r.Method == http.MethodDelete:
			mu.Lock()
			deleted = append(deleted, r.URL.EscapedPath())
			mu.Unlock()
			http.NotFound(w, r) // already gone: must not fail the call
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "tok")
	if err := c.RemoveLabelsWithPrefix(context.Background(), "acme", "widget", 4, "size/", []string{"size/S"}); err != nil {
		t.Fatalf("a 404 on delete must be tolerated: %v", err)
	}
	if len(deleted) != 1 || deleted[0] != "/repos/acme/widget/issues/4/labels/size%2FXS" {
		t.Fatalf("expected only size/XS to be deleted with an escaped slash, got %v", deleted)
	}
}
