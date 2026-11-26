package analysis

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAnalyzeGoCFGAndDataFlow(t *testing.T) {
	dir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, "svc"), 0o755)

	// Positive cases: resource leak, missing defer Unlock on early return, discarded cancel, tx without Rollback.
	_ = os.WriteFile(filepath.Join(dir, "svc", "bad.go"), []byte(`package svc

import (
	"context"
	"database/sql"
	"net/http"
	"sync"
)

func FetchLeak(u string) error {
	resp, err := http.Get(u)
	if err != nil {
		return err
	}
	_ = resp.StatusCode
	return nil
}

func BadLock(mu *sync.Mutex, fail bool) int {
	mu.Lock()
	if fail {
		return -1
	}
	mu.Unlock()
	return 1
}

func CtxLeak(parent context.Context) {
	ctx, _ := context.WithTimeout(parent, 5)
	_ = ctx
}

func TxNoRollback(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	return tx.Commit()
}
`), 0o644)

	// Negative trap cases: properly closed/deferred/rolled-back resources must produce 0 findings.
	_ = os.WriteFile(filepath.Join(dir, "svc", "good.go"), []byte(`package svc

import (
	"context"
	"database/sql"
	"net/http"
	"sync"
)

func FetchSafe(u string) error {
	resp, err := http.Get(u)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

func GoodLock(mu *sync.Mutex, fail bool) int {
	mu.Lock()
	defer mu.Unlock()
	if fail {
		return -1
	}
	return 1
}

func CtxSafe(parent context.Context) {
	ctx, cancel := context.WithTimeout(parent, 5)
	defer cancel()
	_ = ctx
}

func TxSafe(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	return tx.Commit()
}
`), 0o644)

	badFindings := AnalyzeGoCFGAndDataFlow(dir, []string{"svc/bad.go"}, "sha1")
	if len(badFindings) < 4 {
		t.Fatalf("expected >= 4 CFG/dataflow findings in bad.go, got %d: %+v", len(badFindings), badFindings)
	}

	goodFindings := AnalyzeGoCFGAndDataFlow(dir, []string{"svc/good.go"}, "sha1")
	if len(goodFindings) != 0 {
		t.Fatalf("expected 0 false positives in good.go, got %+v", goodFindings)
	}
}

func TestAnalyzeSecurityInvariantsASTIgnoresComments(t *testing.T) {
	baseDir := t.TempDir()
	headDir := t.TempDir()
	_ = os.WriteFile(filepath.Join(baseDir, "hook.go"), []byte("package hook\n\n// VerifySignature(sec, body, sig)\nfunc Handle(ok bool) bool { return ok }\n"), 0o644)
	_ = os.WriteFile(filepath.Join(headDir, "hook.go"), []byte("package hook\n\n// comment updated\nfunc Handle(ok bool) bool { return ok }\n"), 0o644)

	diff := "diff --git a/hook.go b/hook.go\n+++ b/hook.go\n@@ -3,1 +3,1 @@\n-// VerifySignature(sec, body, sig)\n+// comment updated\n"
	findings := AnalyzeSecurityInvariantsAST(baseDir, headDir, diff, "sha2")
	for _, f := range findings {
		if f.RuleID == "CS-INV-001" {
			t.Fatalf("comment removal must not trigger CS-INV-001, got: %+v", f)
		}
	}
}
