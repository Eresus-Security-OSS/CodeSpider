package codeintel

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIndexerContentAddressedCacheAndCallGraph(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "pkg"), 0o755); err != nil {
		t.Fatal(err)
	}
	src := `package pkg

import "context"

type User struct {
	ID string ` + "`json:\"user_id\"`" + `
}

func Helper(ctx context.Context) error { return nil }

func Handler(ctx context.Context) error { return Helper(ctx) }
`
	testSrc := `package pkg

import (
	"context"
	"testing"
)

func TestHandler(t *testing.T) {
	_ = Handler(context.Background())
}
`
	if err := os.WriteFile(filepath.Join(dir, "pkg", "svc.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "pkg", "svc_test.go"), []byte(testSrc), 0o644); err != nil {
		t.Fatal(err)
	}

	idx := NewIndexer()
	snap, err := idx.IndexWorktree(dir, "sha1")
	if err != nil {
		t.Fatalf("IndexWorktree failed: %v", err)
	}
	if idx.CacheLen() != 2 {
		t.Fatalf("expected 2 cached files, got %d", idx.CacheLen())
	}

	userSym, ok := snap.Symbols["pkg.User"]
	if !ok || userSym.JSONTags["ID"] != "user_id" {
		t.Fatalf("unexpected User symbol: %+v", userSym)
	}
	helperSym, ok := snap.Symbols["pkg.Helper"]
	if !ok || !helperSym.TakesContext || !helperSym.ReturnsError {
		t.Fatalf("unexpected Helper symbol: %+v", helperSym)
	}

	tests := snap.ImpactedTests([]string{"pkg.Helper"}, 3)
	if len(tests) != 1 || tests[0] != "pkg/svc_test.go:TestHandler" {
		t.Fatalf("unexpected impacted tests: %#v", tests)
	}

	// Re-indexing unchanged worktree reuses content-addressed cache
	if _, err := idx.IndexWorktree(dir, "sha2"); err != nil {
		t.Fatal(err)
	}
	if idx.CacheLen() != 2 {
		t.Fatalf("expected cache size to remain 2, got %d", idx.CacheLen())
	}
}

func TestIndexerGenericsAliasesInterfacesAndBuildTags(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "api"), 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/demo\n\ngo 1.26\n"), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "api", "types.go"), []byte(`package api

type Store interface {
	Get(id string) ([]byte, error)
	Put(id string, data []byte) error
}

type AliasID = string

func Map[T any, R comparable](in []T, fn func(T) R) []R { return nil }
`), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "api", "ignored.go"), []byte(`//go:build ignore

package api

func ShouldNotBeIndexed() {}
`), 0o644)

	idx := NewIndexer()
	snap, err := idx.IndexWorktree(dir, "head1")
	if err != nil {
		t.Fatal(err)
	}
	if snap.ModulePath != "example.com/demo" {
		t.Fatalf("expected module path example.com/demo, got %q", snap.ModulePath)
	}
	if _, exists := snap.Symbols["api.ShouldNotBeIndexed"]; exists {
		t.Fatal("expected //go:build ignore file to be skipped")
	}
	if ps := snap.Packages["api"]; ps == nil || len(ps.SkippedBuildTagFiles) != 1 {
		t.Fatalf("expected 1 skipped build tag file, got %+v", ps)
	}
	iface := snap.Symbols["api.Store"]
	if iface.Kind != "interface" || len(iface.InterfaceMethods) != 2 {
		t.Fatalf("expected interface Store with 2 methods, got %+v", iface)
	}
	alias := snap.Symbols["api.AliasID"]
	if !alias.IsAlias || alias.Kind != "alias" {
		t.Fatalf("expected AliasID to be marked IsAlias, got %+v", alias)
	}
	gen := snap.Symbols["api.Map"]
	if len(gen.TypeParams) != 2 || !strings.Contains(gen.Signature, "[T any, R comparable]") {
		t.Fatalf("expected generic TypeParams in Map, got %+v", gen)
	}
}
