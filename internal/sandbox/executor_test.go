package sandbox

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDisabledSandboxReturnsInconclusiveNeverHostExec(t *testing.T) {
	exec := NewExecutor(Config{Mode: "disabled"})
	res := exec.RunGoTest(context.Background(), t.TempDir(), ".", "TestAnything", "")
	if res.Status != StatusUnavailable {
		t.Fatalf("expected StatusUnavailable when disabled, got %s", res.Status)
	}
	diff := exec.RunDifferentialGoTest(context.Background(), t.TempDir(), t.TempDir(), ".", "TestAnything", "")
	if diff.Outcome != OutcomeInconclusive {
		t.Fatalf("expected OutcomeInconclusive when disabled, got %s", diff.Outcome)
	}
}

func TestContainerArgsEnforceHardening(t *testing.T) {
	exec := NewExecutor(Config{Mode: "container", Runtime: "docker", Image: "golang:1.26-trixie@sha256:" + strings.Repeat("a", 64)})
	args := exec.buildContainerArgs("/tmp/ws", "internal/pkg", "TestBug")
	joined := strings.Join(args, " ")
	for _, flag := range []string{
		"--network=none",
		"--read-only",
		"--user 65532:65532",
		"--cap-drop=ALL",
		"--security-opt=no-new-privileges",
		"--pids-limit=64",
		"--memory=512m",
		"-v /tmp/ws:/workspace-ro:ro",
		"/work/internal/pkg",
	} {
		if !strings.Contains(joined, flag) {
			t.Fatalf("missing required hardening flag %q in %q", flag, joined)
		}
	}

	digestReq := NewExecutor(Config{Mode: "container", Runtime: "sh", Image: "golang:1.26-trixie", RequireImageDigest: true})
	res := digestReq.RunGoTest(context.Background(), t.TempDir(), ".", "TestBug", "")
	if res.Status != StatusUnavailable || !strings.Contains(res.Output, "@sha256:") {
		t.Fatalf("expected digest requirement failure, got %+v", res)
	}

	// Ensure package_dir is passed as a positional arg to sh -c, never interpolated into the shell command.
	injArgs := exec.buildContainerArgs("/tmp/ws", "pkg/$(id);evil", "TestBug")
	if len(injArgs) < 3 || injArgs[len(injArgs)-2] != "_" || injArgs[len(injArgs)-1] != "/work/pkg/$(id);evil" {
		t.Fatalf("expected containerWorkdir as positional $1 argument, got tail: %#v", injArgs[len(injArgs)-4:])
	}
	shellScript := injArgs[len(injArgs)-3]
	if strings.Contains(shellScript, "$(id)") || !strings.Contains(shellScript, `cd -- "$1"`) {
		t.Fatalf("shell script must not interpolate containerWorkdir: %q", shellScript)
	}

	// cleanRelSubdir rejects rooted and traversal paths.
	for _, bad := range []string{"/etc", `\Windows`, "../escape"} {
		if _, err := cleanRelSubdir("", bad); err == nil {
			t.Fatalf("expected cleanRelSubdir(%q) to fail", bad)
		}
	}

	// copyWorkspaceWithoutGit skips case-variant .GIT directories.
	src := t.TempDir()
	dst := t.TempDir()
	_ = os.MkdirAll(filepath.Join(src, ".GIT"), 0o755)
	_ = os.WriteFile(filepath.Join(src, ".GIT", "config"), []byte("secret"), 0o644)
	_ = os.WriteFile(filepath.Join(src, "main.go"), []byte("package main\n"), 0o644)
	if err := copyWorkspaceWithoutGit(src, dst); err != nil {
		t.Fatalf("copyWorkspaceWithoutGit failed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dst, ".GIT")); !os.IsNotExist(err) {
		t.Fatalf("expected .GIT directory to be skipped, stat err=%v", err)
	}
}
