package semdiff

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Eresus-Security-OSS/CodeSpider/internal/codeintel"
)

func TestSemanticDiffRenameAndEquivalentRefactor(t *testing.T) {
	baseDir := t.TempDir()
	headDir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(baseDir, "svc"), 0o755)
	_ = os.MkdirAll(filepath.Join(headDir, "svc"), 0o755)

	_ = os.WriteFile(filepath.Join(baseDir, "svc", "a.go"), []byte(`package svc

func ComputeTotal(a, b int) int {
	if a < 0 {
		return b
	}
	return a + b
}

func Stable(x int) int {
	return x * 2
}
`), 0o644)

	_ = os.WriteFile(filepath.Join(headDir, "svc", "a.go"), []byte(`package svc

// Renamed function with identical AST body
func CalculateTotal(a, b int) int {
	if a < 0 {
		return b
	}
	return a + b
}

// Comment-only change
func Stable(x int) int {
	return x * 2
}
`), 0o644)

	idx := codeintel.NewIndexer()
	bSnap, err := idx.IndexWorktree(baseDir, "b1")
	if err != nil {
		t.Fatal(err)
	}
	hSnap, err := idx.IndexWorktree(headDir, "h1")
	if err != nil {
		t.Fatal(err)
	}

	diff := "diff --git a/svc/a.go b/svc/a.go\n+++ b/svc/a.go\n@@ -1,3 +1,4 @@\n+// Comment-only change\n"
	sum := Analyze(Input{
		BaseWorktree: baseDir,
		HeadWorktree: headDir,
		BaseSnap:     bSnap,
		HeadSnap:     hSnap,
		Diff:         diff,
		ChangedPaths: []string{"svc/a.go"},
	})

	foundRename := false
	foundEquiv := false
	for _, c := range sum.Changes {
		if c.Kind == ChangeFuncRenamed && c.OldSymbol == "svc.ComputeTotal" && c.Symbol == "svc.CalculateTotal" {
			foundRename = true
		}
		if c.Kind == ChangeEquivalentRefactor && c.Symbol == "svc.Stable" {
			foundEquiv = true
		}
	}
	if !foundRename {
		t.Fatalf("expected ChangeFuncRenamed for ComputeTotal->CalculateTotal, got %+v", sum.Changes)
	}
	if !foundEquiv {
		t.Fatalf("expected ChangeEquivalentRefactor for Stable, got %+v", sum.Changes)
	}
	if sum.PrunedDiff != "" {
		t.Fatalf("expected comment-only diff to be pruned, got %q", sum.PrunedDiff)
	}
}
