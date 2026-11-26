package sandbox

import (
	"context"
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
}
