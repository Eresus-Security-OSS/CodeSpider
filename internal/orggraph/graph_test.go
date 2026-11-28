package orggraph

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/Eresus-Security-OSS/CodeSpider/internal/codeintel"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/policy"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/workspace"
)

func TestOrgGraphACLIsolationAndConfidence(t *testing.T) {
	g, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	snapA := &codeintel.Snapshot{
		CommitSHA:  "shaA",
		ModulePath: "github.com/acme/auth",
		Packages:   map[string]*codeintel.PackageSummary{"pkg": {PkgPath: "pkg"}},
		Symbols: map[string]codeintel.Symbol{
			"pkg.Verify": {ID: "pkg.Verify", Name: "Verify", Kind: "func", File: "pkg/auth.go", Exported: true},
		},
	}
	snapAllowed := &codeintel.Snapshot{
		CommitSHA: "shaB",
		Packages: map[string]*codeintel.PackageSummary{
			"srv": {PkgPath: "srv", Imports: []string{"github.com/acme/auth/pkg"}},
		},
		Symbols: map[string]codeintel.Symbol{
			"srv.Handler": {ID: "srv.Handler", Name: "Handler", Kind: "func", File: "srv/h.go", Calls: []string{"auth.Verify"}},
		},
	}
	snapSecret := &codeintel.Snapshot{
		CommitSHA: "shaC",
		Packages: map[string]*codeintel.PackageSummary{
			"sec": {PkgPath: "sec", Imports: []string{"github.com/acme/auth/pkg"}},
		},
	}

	if err := g.IndexRepoSnapshot("acme/auth", "shaA", snapA, nil); err != nil {
		t.Fatal(err)
	}
	if err := g.IndexRepoSnapshot("acme/web", "shaB", snapAllowed, nil); err != nil {
		t.Fatal(err)
	}
	if err := g.IndexRepoSnapshot("other/private", "shaC", snapSecret, nil); err != nil {
		t.Fatal(err)
	}

	// Fork PR gets ZERO cross-repo results.
	forkPerms := policy.EvaluatePermissions(policy.Input{Owner: "acme", IsFork: true, AllowSameOwnerCrossRepo: true})
	forkImpact := g.QueryImpact("acme/auth", "github.com/acme/auth", []string{"pkg.Verify"}, forkPerms)
	if len(forkImpact.VerifiedImpacts) != 0 || len(forkImpact.InferredImpacts) != 0 {
		t.Fatalf("expected fork PR to receive 0 cross-repo impacts, got %+v", forkImpact)
	}

	// Same-owner collaborator sees acme/web (verified import + inferred call) but NEVER other/private.
	collabPerms := policy.EvaluatePermissions(policy.Input{Owner: "acme", IsFork: false, AllowSameOwnerCrossRepo: true})
	imp := g.QueryImpact("acme/auth", "github.com/acme/auth", []string{"pkg.Verify"}, collabPerms)
	if len(imp.VerifiedImpacts) != 1 || imp.VerifiedImpacts[0].Repo != "acme/web" {
		t.Fatalf("expected 1 verified impact for acme/web, got %+v", imp)
	}
	if len(imp.InferredImpacts) != 1 || imp.InferredImpacts[0].Repo != "acme/web" {
		t.Fatalf("expected 1 inferred impact for acme/web, got %+v", imp)
	}
}

func TestSpeculativeMergeCheckDetectsConflict(t *testing.T) {
	ctx := context.Background()
	origin := t.TempDir()
	runGit := func(args ...string) string {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = origin
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=T", "GIT_AUTHOR_EMAIL=t@e.com",
			"GIT_COMMITTER_NAME=T", "GIT_COMMITTER_EMAIL=t@e.com",
		)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, string(out))
		}
		return string(out)
	}

	runGit("init", "-b", "main")
	_ = os.WriteFile(filepath.Join(origin, "cfg.go"), []byte("package cfg\nconst Port = 8080\n"), 0o644)
	runGit("add", ".")
	runGit("commit", "-m", "base")

	runGit("checkout", "-b", "pr-a")
	_ = os.WriteFile(filepath.Join(origin, "cfg.go"), []byte("package cfg\nconst Port = 9090\n"), 0o644)
	runGit("add", ".")
	runGit("commit", "-m", "pr-a")
	shaA := string(func() []byte {
		out, _ := exec.Command("git", "-C", origin, "rev-parse", "HEAD").Output()
		return out
	}())
	shaA = shaA[:len(shaA)-1]

	runGit("checkout", "main")
	runGit("checkout", "-b", "pr-b")
	_ = os.WriteFile(filepath.Join(origin, "cfg.go"), []byte("package cfg\nconst Port = 7070\n"), 0o644)
	runGit("add", ".")
	runGit("commit", "-m", "pr-b")
	shaB := string(func() []byte {
		out, _ := exec.Command("git", "-C", origin, "rev-parse", "HEAD").Output()
		return out
	}())
	shaB = shaB[:len(shaB)-1]

	ws := workspace.NewManager(t.TempDir(), "")
	res, err := SpeculativeMergeCheck(ctx, ws, "acme", "app", origin, shaA, shaB)
	if err != nil {
		t.Fatalf("SpeculativeMergeCheck failed: %v", err)
	}
	if !res.HasConflict {
		t.Fatalf("expected merge conflict between PR A and PR B, got %+v", res)
	}

	if _, err := SpeculativeMergeCheck(ctx, ws, "acme", "app", origin, shaA, "--strategy-option=ours"); err == nil {
		t.Fatal("expected flag-like prBSHA to be rejected")
	}
	if _, err := SpeculativeMergeCheck(ctx, ws, "acme", "app", origin, "-bad", shaB); err == nil {
		t.Fatal("expected flag-like prASHA to be rejected")
	}
	if _, err := SpeculativeMergeCheck(ctx, ws, "acme", "app", origin, shaA, "main"); err == nil {
		t.Fatal("expected non-SHA revision to be rejected")
	}
}
