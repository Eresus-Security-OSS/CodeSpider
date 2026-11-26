package analysis

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPipelineDetectsContractsSecurityMigrationsIaCAndCaches(t *testing.T) {
	baseDir := t.TempDir()
	headDir := t.TempDir()

	if err := os.MkdirAll(filepath.Join(baseDir, "api"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(headDir, "api"), 0o755); err != nil {
		t.Fatal(err)
	}

	_ = os.WriteFile(filepath.Join(baseDir, "api", "handler.go"), []byte(`package api
import "context"
type Resp struct { Total int `+"`json:\"total\"`"+` }
func Charge(ctx context.Context, amt int) error { return nil }
func Hook(sig []byte) bool { return VerifySignature(sig) }
func VerifySignature(s []byte) bool { return len(s) > 0 }
`), 0o644)

	_ = os.WriteFile(filepath.Join(headDir, "api", "handler.go"), []byte(`package api
import "os/exec"
type Resp struct { Total int `+"`json:\"total_cents\"`"+` }
func Charge(amt int) {}
func Run(userCmd string) { _ = exec.Command("sh", "-c", userCmd) }
func VerifySignature(s []byte) bool { return len(s) > 0 }
`), 0o644)

	diff := strings.Join([]string{
		"diff --git a/api/handler.go b/api/handler.go",
		"+++ b/api/handler.go",
		"@@ -5,1 +5,1 @@",
		"-func Hook(sig []byte) bool { return VerifySignature(sig) }",
		"+func Run(userCmd string) { _ = exec.Command(\"sh\", \"-c\", userCmd) }",
		"diff --git a/migrations/001.up.sql b/migrations/001.up.sql",
		"+++ b/migrations/001.up.sql",
		"@@ -1,0 +1,1 @@",
		"+DROP TABLE users;",
		"diff --git a/docker-compose.yaml b/docker-compose.yaml",
		"+++ b/docker-compose.yaml",
		"@@ -1,0 +1,2 @@",
		"+image: app:latest",
		"+privileged: true",
	}, "\n")

	pipe := NewPipeline()
	in := Input{
		RepoSlug:      "acme/app",
		PRNumber:      1,
		BaseSHA:       "base123",
		HeadSHA:       "head456",
		BaseWorktree:  baseDir,
		HeadWorktree:  headDir,
		Diff:          diff,
		ChangedPaths:  []string{"api/handler.go", "migrations/001.up.sql", "docker-compose.yaml"},
		ForbidImports: map[string][]string{"api": {"os/exec"}},
	}

	rep := pipe.Run(in)
	if rep.CacheHit {
		t.Fatal("expected first run not to be a cache hit")
	}

	seenRules := make(map[string]bool)
	for _, f := range rep.Findings {
		seenRules[f.RuleID] = true
	}
	for _, want := range []string{"CS-API-002", "CS-API-003", "CS-SEC-001", "CS-INV-001", "CS-MIG-001", "CS-MIG-004", "CS-IAC-001", "CS-IAC-004"} {
		if !seenRules[want] {
			t.Fatalf("expected deterministic rule %s to fire; got rules: %v", want, seenRules)
		}
	}

	// Second identical run hits incremental cache
	rep2 := pipe.Run(in)
	if !rep2.CacheHit {
		t.Fatal("expected second identical run to hit incremental cache")
	}

	// Cross-PR semantic conflict detection
	in2 := in
	in2.PRNumber = 2
	in2.HeadSHA = "head999"
	repPR2 := pipe.Run(in2)
	if len(repPR2.Conflicts) == 0 {
		t.Fatal("expected cross-PR semantic conflict between PR #1 and PR #2")
	}
}
