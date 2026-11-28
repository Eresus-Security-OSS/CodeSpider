package gitea

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

func TestRemoveLabelsWithPrefixKeepsCurrentAndUnrelatedLabels(t *testing.T) {
	var mu sync.Mutex
	var deleted []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/repos/acme/api/issues/3/labels":
			_, _ = w.Write([]byte(`[{"id":7,"name":"size/XS"},{"id":8,"name":"size/S"},{"id":9,"name":"bug"},{"id":10,"name":"Size/L"}]`))
		case r.Method == http.MethodDelete:
			mu.Lock()
			deleted = append(deleted, r.URL.Path)
			mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "tok")
	if err := c.RemoveLabelsWithPrefix(context.Background(), "acme", "api", 3, "size/", []string{"size/S", "tests"}); err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{
		"/api/v1/repos/acme/api/issues/3/labels/7":  true, // stale bucket
		"/api/v1/repos/acme/api/issues/3/labels/10": true, // prefix match is case-insensitive
	}
	if len(deleted) != len(want) {
		t.Fatalf("expected %d deletions, got %v", len(want), deleted)
	}
	for _, p := range deleted {
		if !want[p] {
			t.Fatalf("unexpected deletion %s (kept size/S and bug must not be removed)", p)
		}
	}

	if err := c.RemoveLabelsWithPrefix(context.Background(), "acme", "api", 3, "", nil); err == nil {
		t.Fatal("an empty prefix would strip every label and must be rejected")
	}
}
