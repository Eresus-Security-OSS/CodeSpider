package workspace

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestResolveSafePath(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()

	if err := os.MkdirAll(filepath.Join(root, "pkg"), 0o755); err != nil {
		t.Fatal(err)
	}
	existing := filepath.Join(root, "pkg", "main.go")
	if err := os.WriteFile(existing, []byte("package pkg\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	secretFile := filepath.Join(outside, "secret.txt")
	if err := os.WriteFile(secretFile, []byte("top-secret"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Normal existing file
	got, err := ResolveSafePath(root, "pkg/main.go")
	if err != nil {
		t.Fatalf("expected valid path, got error: %v", err)
	}
	if !strings.HasSuffix(got, filepath.Join("pkg", "main.go")) {
		t.Fatalf("unexpected resolved path: %s", got)
	}

	// Non-existent new file inside valid directory
	gotNew, err := ResolveSafePath(root, "pkg/newdir/new.go")
	if err != nil {
		t.Fatalf("expected valid non-existent path, got error: %v", err)
	}
	if !strings.HasSuffix(gotNew, filepath.Join("pkg", "newdir", "new.go")) {
		t.Fatalf("unexpected new resolved path: %s", gotNew)
	}

	// Reject absolute and traversal paths
	if _, err := ResolveSafePath(root, "/etc/passwd"); err == nil {
		t.Fatal("expected error for absolute path")
	}
	if runtime.GOOS == "windows" {
		for _, bad := range []string{`\Windows\System32`, `C:relative.txt`} {
			if _, err := ResolveSafePath(root, bad); err == nil {
				t.Fatalf("expected error for non-relative Windows path %q", bad)
			}
		}
	}
	if _, err := ResolveSafePath(root, "../escape.txt"); err == nil {
		t.Fatal("expected error for parent traversal")
	}

	// Reject symlink pointing outside workspace
	linkPath := filepath.Join(root, "pkg", "leak")
	if err := os.Symlink(outside, linkPath); err != nil {
		t.Skipf("symlinks not supported: %v", err)
	}
	if _, err := ResolveSafePath(root, "pkg/leak/secret.txt"); err == nil {
		t.Fatal("expected error for symlink escaping workspace")
	}

	// Reject broken symlink pointing outside workspace
	brokenLink := filepath.Join(root, "broken-leak")
	if err := os.Symlink(filepath.Join(outside, "does-not-exist"), brokenLink); err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveSafePath(root, "broken-leak"); err == nil {
		t.Fatal("expected error for broken symlink escaping workspace")
	}
}

func TestGitAuthArgsAndRedaction(t *testing.T) {
	token := "super-secret-gitea-token"
	args := gitAuthArgs("https://gitea.example.com/acme/api.git", token)
	if len(args) != 2 || args[0] != "-c" || !strings.HasPrefix(args[1], "http.extraHeader=Authorization: Basic ") {
		t.Fatalf("unexpected gitAuthArgs: %#v", args)
	}
	if strings.Contains(args[1], token) {
		t.Fatal("expected Basic auth header to encode token rather than embed raw token")
	}

	if got := gitAuthArgs("ssh://git@gitea.example.com/acme/api.git", token); got != nil {
		t.Fatalf("expected nil auth args for ssh URL, got %#v", got)
	}

	mgr := NewManager(t.TempDir(), token)
	err := mgr.runGit(context.Background(), "", "clone", "https://gitea.example.com/does-not-exist", filepath.Join(t.TempDir(), "dst"))
	if err == nil {
		t.Fatal("expected git clone error")
	}
	if strings.Contains(err.Error(), token) {
		t.Fatalf("token leaked in git error: %v", err)
	}
	redacted := mgr.redact("error using " + token)
	if strings.Contains(redacted, token) || !strings.Contains(redacted, "[REDACTED]") {
		t.Fatalf("expected token to be redacted, got: %q", redacted)
	}
}

func TestCheckoutDiffCommitAndCleanup(t *testing.T) {
	ctx := context.Background()
	originDir := t.TempDir()

	runGitCmd := func(dir string, args ...string) string {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=Tester",
			"GIT_AUTHOR_EMAIL=tester@example.com",
			"GIT_COMMITTER_NAME=Tester",
			"GIT_COMMITTER_EMAIL=tester@example.com",
		)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v failed: %v\n%s", args, err, string(out))
		}
		return strings.TrimSpace(string(out))
	}

	runGitCmd(originDir, "init", "-b", "main")
	if err := os.WriteFile(filepath.Join(originDir, "app.go"), []byte("package main\n\nfunc v() int { return 1 }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runGitCmd(originDir, "add", ".")
	runGitCmd(originDir, "commit", "-m", "initial")
	sha1 := runGitCmd(originDir, "rev-parse", "HEAD")

	if err := os.WriteFile(filepath.Join(originDir, "app.go"), []byte("package main\n\nfunc v() int { return 2 }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runGitCmd(originDir, "add", ".")
	runGitCmd(originDir, "commit", "-m", "second")
	sha2 := runGitCmd(originDir, "rev-parse", "HEAD")

	dataDir := t.TempDir()
	mgr := NewManager(dataDir, "tok-123")

	wtDir, cleanup, err := mgr.CheckoutPR(ctx, "acme", "app", originDir, sha2)
	if err != nil {
		t.Fatalf("CheckoutPR failed: %v", err)
	}
	defer cleanup()

	diff, err := mgr.DiffCommits(ctx, wtDir, sha1, sha2)
	if err != nil {
		t.Fatalf("DiffCommits failed: %v", err)
	}
	if !strings.Contains(diff, "+func v() int { return 2 }") {
		t.Fatalf("unexpected diff output:\n%s", diff)
	}

	if _, err := mgr.DiffCommits(ctx, wtDir, "--output=/tmp/x", sha2); err == nil {
		t.Fatal("expected error for invalid SHA")
	}

	cleanup()
	if _, err := os.Stat(wtDir); !os.IsNotExist(err) {
		t.Fatalf("expected worktree %s to be removed", wtDir)
	}

	// Create a stale worktree directory and verify CleanupStaleWorktrees removes it.
	stale := filepath.Join(dataDir, "worktrees", "stale-dir")
	if err := os.MkdirAll(stale, 0o755); err != nil {
		t.Fatal(err)
	}
	mgr.CleanupStaleWorktrees(ctx)
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatalf("expected stale worktree dir %s to be cleaned up", stale)
	}
}

func TestSearchCachedMirrorsForensicsAndCommitPatches(t *testing.T) {
	ctx := context.Background()
	runGitCmd := func(dir string, args ...string) string {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=Tester",
			"GIT_AUTHOR_EMAIL=tester@example.com",
			"GIT_COMMITTER_NAME=Tester",
			"GIT_COMMITTER_EMAIL=tester@example.com",
		)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v failed: %v\n%s", args, err, string(out))
		}
		return strings.TrimSpace(string(out))
	}

	// Repo 1: acme/billing
	billingOrigin := t.TempDir()
	runGitCmd(billingOrigin, "init", "-b", "main")
	if err := os.WriteFile(filepath.Join(billingOrigin, "service.go"), []byte("package billing\n\nfunc Charge() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runGitCmd(billingOrigin, "add", ".")
	runGitCmd(billingOrigin, "commit", "-m", "fix: resolve race condition in Charge")
	if err := os.WriteFile(filepath.Join(billingOrigin, "service.go"), []byte("package billing\n\nvar tempKey = \"AKIAIOSFODNN7EXAMPLE\"\nfunc Charge() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runGitCmd(billingOrigin, "add", ".")
	runGitCmd(billingOrigin, "commit", "-m", "wip add key")
	if err := os.WriteFile(filepath.Join(billingOrigin, "service.go"), []byte("package billing\n\nfunc Charge() { /* clean */ }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runGitCmd(billingOrigin, "add", ".")
	runGitCmd(billingOrigin, "commit", "-m", "remove key")
	headSHA := runGitCmd(billingOrigin, "rev-parse", "HEAD")

	// Repo 2: acme/checkout (calls billing.Charge)
	checkoutOrigin := t.TempDir()
	runGitCmd(checkoutOrigin, "init", "-b", "main")
	if err := os.WriteFile(filepath.Join(checkoutOrigin, "client.go"), []byte("package checkout\n\nfunc Pay() { Charge() }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runGitCmd(checkoutOrigin, "add", ".")
	runGitCmd(checkoutOrigin, "commit", "-m", "call billing")

	mgr := NewManager(t.TempDir(), "")
	wtBilling, cleanBilling, err := mgr.CheckoutPR(ctx, "acme", "billing", billingOrigin, headSHA)
	if err != nil {
		t.Fatalf("CheckoutPR billing failed: %v", err)
	}
	defer cleanBilling()

	_, cleanCheckout, err := mgr.CheckoutPR(ctx, "acme", "checkout", checkoutOrigin, "")
	if err != nil {
		t.Fatalf("CheckoutPR checkout failed: %v", err)
	}
	defer cleanCheckout()

	// Cross-repo search from acme/billing should find acme/checkout
	cross, err := mgr.SearchCachedMirrors(ctx, "acme/billing", `Charge\(`, 10)
	if err != nil {
		t.Fatalf("SearchCachedMirrors failed: %v", err)
	}
	if !strings.Contains(cross, "[acme/checkout] client.go:3:") || strings.Contains(cross, "[acme/billing]") {
		t.Fatalf("unexpected cross-repo matches:\n%s", cross)
	}

	// FileForensics should flag prior fix commit
	forensics, err := mgr.FileForensics(ctx, wtBilling, "service.go", 1, 3)
	if err != nil {
		t.Fatalf("FileForensics failed: %v", err)
	}
	if !strings.Contains(forensics, "PRIOR FIX/REVERT") {
		t.Fatalf("expected PRIOR FIX/REVERT marker in forensics:\n%s", forensics)
	}

	// CommitPatches should capture intermediate commit containing AKIA...
	patches, err := mgr.CommitPatches(ctx, wtBilling, "main~2", headSHA)
	if err != nil {
		t.Fatalf("CommitPatches failed: %v", err)
	}
	if !strings.Contains(patches, "AKIAIOSFODNN7EXAMPLE") {
		t.Fatalf("expected intermediate commit patch to contain secret:\n%s", patches)
	}

	// Origin pinning rejects mismatched HTTP(S) cloneURL
	pinned := NewManager(t.TempDir(), "tok").WithAllowedOrigin("https://gitea.internal")
	if _, _, err := pinned.CheckoutPR(ctx, "acme", "app", "https://evil.example.com/acme/app.git", ""); err == nil || !strings.Contains(err.Error(), "untrusted clone URL origin") {
		t.Fatalf("expected untrusted clone URL origin error, got: %v", err)
	}

	// Allowlist restricts cross-repo search
	deniedCross, err := mgr.SearchCachedMirrorsWithAllowlist(ctx, "acme/billing", `Charge\(`, nil, []string{"acme/other"}, 10)
	if err != nil || strings.Contains(deniedCross, "acme/checkout") {
		t.Fatalf("expected acme/checkout to be excluded by allowlist, got: %q (err=%v)", deniedCross, err)
	}
}

func TestReadWriteSafeFileRejectsSymlinksAndGit(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	_ = os.WriteFile(filepath.Join(outside, "ext.txt"), []byte("secret"), 0o644)
	if err := WriteSafeFile(root, "sub/ok.txt", []byte("hello")); err != nil {
		t.Fatalf("WriteSafeFile failed: %v", err)
	}
	got, err := ReadSafeFile(root, "sub/ok.txt", 1024)
	if err != nil || string(got) != "hello" {
		t.Fatalf("ReadSafeFile failed: %v (%q)", err, string(got))
	}
	if err := WriteSafeFile(root, "sub/ok.txt", []byte("abc")); err != nil {
		t.Fatalf("overwriting existing file: %v", err)
	}
	got, err = ReadSafeFile(root, "sub/ok.txt", 1024)
	if err != nil || string(got) != "abc" {
		t.Fatalf("expected overwritten file without trailing bytes, got %q: %v", got, err)
	}
	for _, bad := range []string{".GIT/hooks/pre-commit", "sub/.Git", "sub/.GIT/config"} {
		if err := WriteSafeFile(root, bad, []byte("bad")); err == nil {
			t.Fatalf("expected case-insensitive .git write %q to be rejected", bad)
		}
	}
	if err := WriteSafeFile(root, ".git/hooks/pre-commit", []byte("bad")); err == nil {
		t.Fatal("expected .git write to be rejected")
	}
	mgr := NewManager(t.TempDir(), "")
	for _, tc := range [][2]string{
		{"main:evil", "a.go"},
		{"main", "/etc/passwd"},
		{"main", `\Windows\win.ini`},
	} {
		if _, err := mgr.ReadMirrorFile(context.Background(), "acme", "app", tc[0], tc[1]); err == nil {
			t.Fatalf("expected ReadMirrorFile(%q, %q) to fail", tc[0], tc[1])
		}
	}
	if err := os.Symlink(filepath.Join(outside, "ext.txt"), filepath.Join(root, "link.txt")); err == nil {
		if _, err := ReadSafeFile(root, "link.txt", 1024); err == nil {
			t.Fatal("expected symlink read to be rejected")
		}
		if err := WriteSafeFile(root, "link.txt", []byte("x")); err == nil {
			t.Fatal("expected symlink write to be rejected")
		}
	}
}
