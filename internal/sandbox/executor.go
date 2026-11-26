// Package sandbox provides container-isolated execution and differential base-vs-head testing.
// Untrusted PR code is never executed directly on the daemon host.
package sandbox

import (
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Status describes the execution outcome of a sandboxed test run.
type Status string

const (
	StatusPassed      Status = "passed"
	StatusFailed      Status = "failed"
	StatusUnavailable Status = "unavailable"
	StatusError       Status = "error"
)

// DifferentialOutcome compares base vs. head test results.
type DifferentialOutcome string

const (
	OutcomeRegression         DifferentialOutcome = "regression"           // Base passed, Head failed
	OutcomePreExistingFailure DifferentialOutcome = "pre_existing_failure" // Both Base and Head failed
	OutcomeNotReproduced      DifferentialOutcome = "not_reproduced"       // Head passed
	OutcomeInconclusive       DifferentialOutcome = "inconclusive"         // Sandbox unavailable or errored
)

// Config controls container sandbox execution limits.
type Config struct {
	Mode               string // "disabled" (default) or "container"
	Runtime            string // "docker" (default) or "podman"
	Image              string // default "golang:1.26-trixie"
	RequireImageDigest bool   // when true, require @sha256:<64-hex> digest pinning
	EnableRace         bool   // run go test -race when container toolchain supports CGO
	Timeout            time.Duration
	MemoryMB           int
	CPUs               string
	PidsLimit          int
}

// Executor runs untrusted Go tests strictly inside isolated containers.
type Executor struct {
	cfg Config
}

// Result holds the output of a single sandboxed test invocation.
type Result struct {
	Status Status `json:"status"`
	Output string `json:"output"`
}

// DifferentialResult compares base and head execution for the same test.
type DifferentialResult struct {
	Outcome    DifferentialOutcome `json:"outcome"`
	BaseResult Result              `json:"base_result"`
	HeadResult Result              `json:"head_result"`
}

var (
	validTestNameRe = regexp.MustCompile(`^Test[A-Za-z0-9_]+$`)
	digestPinnedRe  = regexp.MustCompile(`@sha256:[0-9a-f]{64}$`)
)

// NewExecutor creates a sandbox Executor with safe defaults.
func NewExecutor(cfg Config) *Executor {
	if strings.TrimSpace(cfg.Mode) == "" {
		cfg.Mode = "disabled"
	}
	if strings.TrimSpace(cfg.Runtime) == "" {
		cfg.Runtime = "docker"
	}
	if strings.TrimSpace(cfg.Image) == "" {
		cfg.Image = "golang:1.26-trixie"
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 30 * time.Second
	}
	if cfg.MemoryMB <= 0 {
		cfg.MemoryMB = 512
	}
	if strings.TrimSpace(cfg.CPUs) == "" {
		cfg.CPUs = "1.0"
	}
	if cfg.PidsLimit <= 0 {
		cfg.PidsLimit = 64
	}
	return &Executor{cfg: cfg}
}

// Enabled reports whether container-isolated execution is enabled.
func (e *Executor) Enabled() bool {
	return e != nil && strings.EqualFold(e.cfg.Mode, "container")
}

// RunGoTest executes `go test -race` inside an isolated container with no network and dropped capabilities.
// Never falls back to host execution.
func (e *Executor) RunGoTest(ctx context.Context, worktreeDir, pkgDir, testName, testCode string) Result {
	if !e.Enabled() {
		return Result{
			Status: StatusUnavailable,
			Output: "isolated container sandbox is disabled (set sandbox.mode: container to enable)",
		}
	}
	if !validTestNameRe.MatchString(testName) {
		return Result{
			Status: StatusError,
			Output: fmt.Sprintf("invalid test_name %q; must match ^Test[A-Za-z0-9_]+$", testName),
		}
	}
	if e.cfg.RequireImageDigest && !digestPinnedRe.MatchString(e.cfg.Image) {
		return Result{
			Status: StatusUnavailable,
			Output: fmt.Sprintf("sandbox image %q must be pinned by @sha256:<64-hex> digest", e.cfg.Image),
		}
	}
	if _, err := exec.LookPath(e.cfg.Runtime); err != nil {
		return Result{
			Status: StatusUnavailable,
			Output: fmt.Sprintf("container runtime %q not found in PATH", e.cfg.Runtime),
		}
	}

	relPkg, err := cleanRelSubdir(worktreeDir, pkgDir)
	if err != nil {
		return Result{Status: StatusError, Output: err.Error()}
	}

	tmpCopy, err := os.MkdirTemp("", "codespider-sandbox-*")
	if err != nil {
		return Result{Status: StatusError, Output: err.Error()}
	}
	defer os.RemoveAll(tmpCopy)

	if err := copyWorkspaceWithoutGit(worktreeDir, tmpCopy); err != nil {
		return Result{Status: StatusError, Output: fmt.Sprintf("stage sandbox copy: %v", err)}
	}
	if strings.TrimSpace(testCode) != "" {
		pocFile := filepath.Join(tmpCopy, filepath.FromSlash(relPkg), "codespider_poc_test.go")
		if err := os.WriteFile(pocFile, []byte(testCode), 0o600); err != nil {
			return Result{Status: StatusError, Output: fmt.Sprintf("write poc test: %v", err)}
		}
	}

	args := e.buildContainerArgs(tmpCopy, relPkg, testName)
	runCtx, cancel := context.WithTimeout(ctx, e.cfg.Timeout)
	defer cancel()

	cmd := exec.CommandContext(runCtx, e.cfg.Runtime, args...)
	var out bytes.Buffer
	cmd.Stdout = &limitedBuf{buf: &out, max: 16 * 1024}
	cmd.Stderr = &limitedBuf{buf: &out, max: 16 * 1024}

	if err := cmd.Run(); err != nil {
		if runCtx.Err() != nil {
			return Result{Status: StatusError, Output: "sandbox execution timed out:\n" + out.String()}
		}
		return Result{Status: StatusFailed, Output: out.String()}
	}
	return Result{Status: StatusPassed, Output: out.String()}
}

// RunDifferentialGoTest runs the same test against baseWorktree and headWorktree to separate
// PR-introduced regressions from pre-existing failures.
func (e *Executor) RunDifferentialGoTest(ctx context.Context, baseWorktree, headWorktree, pkgDir, testName, testCode string) DifferentialResult {
	headRes := e.RunGoTest(ctx, headWorktree, pkgDir, testName, testCode)
	if headRes.Status == StatusUnavailable || headRes.Status == StatusError {
		return DifferentialResult{Outcome: OutcomeInconclusive, HeadResult: headRes}
	}
	if headRes.Status == StatusPassed {
		return DifferentialResult{Outcome: OutcomeNotReproduced, HeadResult: headRes}
	}
	if strings.TrimSpace(baseWorktree) == "" {
		return DifferentialResult{Outcome: OutcomeInconclusive, HeadResult: headRes}
	}
	baseRes := e.RunGoTest(ctx, baseWorktree, pkgDir, testName, testCode)
	switch baseRes.Status {
	case StatusPassed:
		return DifferentialResult{Outcome: OutcomeRegression, BaseResult: baseRes, HeadResult: headRes}
	case StatusFailed:
		return DifferentialResult{Outcome: OutcomePreExistingFailure, BaseResult: baseRes, HeadResult: headRes}
	default:
		return DifferentialResult{Outcome: OutcomeInconclusive, BaseResult: baseRes, HeadResult: headRes}
	}
}

func (e *Executor) buildContainerArgs(hostWorkspace, relPkg, testName string) []string {
	containerWorkdir := "/work"
	if relPkg != "." && relPkg != "" {
		containerWorkdir = "/work/" + relPkg
	}
	raceFlag := ""
	cgoEnv := "CGO_ENABLED=0"
	if e.cfg.EnableRace {
		raceFlag = "-race "
		cgoEnv = "CGO_ENABLED=1"
	}
	shellCmd := fmt.Sprintf("cp -R /workspace-ro/. /work/ && cd %s && go test %s-v -count=1 -run '^%s$' .", containerWorkdir, raceFlag, testName)
	return []string{
		"run", "--rm",
		"--network=none",
		"--read-only",
		"--user", "65532:65532",
		"--tmpfs", "/work:rw,exec,nosuid,nodev,size=256m",
		"--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=64m",
		"--tmpfs", "/go-cache:rw,exec,nosuid,nodev,size=256m",
		"-e", "GOCACHE=/go-cache",
		"-e", "GOTMPDIR=/go-cache",
		"-e", "HOME=/tmp",
		"-e", cgoEnv,
		"--cap-drop=ALL",
		"--security-opt=no-new-privileges",
		fmt.Sprintf("--pids-limit=%d", e.cfg.PidsLimit),
		fmt.Sprintf("--memory=%dm", e.cfg.MemoryMB),
		fmt.Sprintf("--cpus=%s", e.cfg.CPUs),
		"-v", hostWorkspace + ":/workspace-ro:ro",
		"-w", "/work",
		e.cfg.Image,
		"sh", "-c", shellCmd,
	}
}

func cleanRelSubdir(root, sub string) (string, error) {
	if strings.TrimSpace(sub) == "" || sub == "." {
		return ".", nil
	}
	if filepath.IsAbs(sub) {
		return "", fmt.Errorf("package_dir must be relative: %s", sub)
	}
	clean := filepath.ToSlash(filepath.Clean(sub))
	if clean == ".." || strings.HasPrefix(clean, "../") {
		return "", fmt.Errorf("package_dir escapes workspace: %s", sub)
	}
	if root != "" {
		info, err := os.Stat(filepath.Join(root, filepath.FromSlash(clean)))
		if err != nil || !info.IsDir() {
			return "", fmt.Errorf("package_dir not found: %s", sub)
		}
	}
	return clean, nil
}

func copyWorkspaceWithoutGit(src, dst string) error {
	const maxFileBytes = 4 << 20
	const maxTotalBytes = 64 << 20
	var totalBytes int64
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Name() == ".git" && d.IsDir() {
			return filepath.SkipDir
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		if !d.Type().IsRegular() {
			return nil // skip symlinks, FIFOs, sockets, and devices
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if info.Size() > maxFileBytes {
			return nil
		}
		if totalBytes+info.Size() > maxTotalBytes {
			return fmt.Errorf("sandbox workspace copy exceeds %d MiB limit", maxTotalBytes>>20)
		}
		totalBytes += info.Size()
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o644)
	})
}

type limitedBuf struct {
	buf *bytes.Buffer
	max int
}

func (w *limitedBuf) Write(p []byte) (int, error) {
	rem := w.max - w.buf.Len()
	if rem > 0 {
		if len(p) > rem {
			w.buf.Write(p[:rem])
		} else {
			w.buf.Write(p)
		}
	}
	return len(p), nil
}
