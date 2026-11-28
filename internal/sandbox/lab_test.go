package sandbox

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Eresus-Security-OSS/CodeSpider/internal/evidence"
)

func TestValidatePoCTestSource(t *testing.T) {
	if err := ValidatePoCTestSource("TestSafe", "package p\nimport \"testing\"\nfunc TestSafe(t *testing.T) {}\n"); err != nil {
		t.Fatalf("expected valid PoC test, got: %v", err)
	}
	if err := ValidatePoCTestSource("TestBad", "package p\nimport (\"os/exec\"; \"testing\")\nfunc TestBad(t *testing.T) { _ = exec.Command }\n"); err == nil {
		t.Fatal("expected os/exec import in PoC test to be blocked")
	}
	if err := ValidatePoCTestSource("TestMissing", "package p\nimport \"testing\"\nfunc TestOther(t *testing.T) {}\n"); err == nil {
		t.Fatal("expected missing test function to fail validation")
	}
}

func TestRunLabDifferentialFlakeCompileAndPatch(t *testing.T) {
	binDir := t.TempDir()
	stateFile := filepath.Join(binDir, "mode.txt")
	mockDocker := filepath.Join(binDir, "docker")
	var script string
	if runtime.GOOS == "windows" {
		mockDocker += ".cmd"
		script = `@echo off
setlocal enabledelayedexpansion
set "args=%*"
echo !args! | findstr /C:":ro" >nul || (
  echo missing read-only mount 1>&2
  exit /b 2
)
set "ws="
:loop
if "%~1"=="" goto done
if "%~1"=="-v" (
  set "vol=%~2"
  set "ws=!vol::/workspace-ro:ro=!"
  shift
)
shift
goto loop
:done
set "mode=normal"
if exist "` + stateFile + `" set /p mode=<"` + stateFile + `"
if "!mode!"=="compile_error" (
  echo FAIL example/pkg [build failed]
  exit /b 2
)
if exist "!ws!\patched.txt" (
  echo PASS
  exit /b 0
)
if exist "!ws!\head.txt" (
  echo --- FAIL: TestBug (0.00s^)
  echo panic: nil pointer dereference
  exit /b 1
)
echo PASS
exit /b 0
`
	} else {
		// Mock container runtime script inspecting mounted host workspace marker and simulating base pass / head fail / patch pass.
		script = `#!/bin/sh
args="$*"
if ! echo "$args" | grep -q ":ro"; then
  echo "missing read-only mount" >&2
  exit 2
fi
ws=$(echo "$args" | sed -n 's/.*-v \([^:]*\):\/workspace-ro:ro.*/\1/p')
mode=$(cat "` + stateFile + `" 2>/dev/null || echo "normal")
if [ "$mode" = "compile_error" ]; then
  echo "FAIL example/pkg [build failed]"
  exit 2
fi
if [ -f "$ws/patched.txt" ]; then
  echo "PASS"
  exit 0
fi
if [ -f "$ws/head.txt" ]; then
  echo "--- FAIL: TestBug (0.00s)"
  echo "panic: nil pointer dereference"
  exit 1
fi
echo "PASS"
exit 0
`
	}
	if err := os.WriteFile(mockDocker, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	baseDir := filepath.Join(t.TempDir(), "base")
	headDir := filepath.Join(t.TempDir(), "head")
	_ = os.MkdirAll(baseDir, 0o755)
	_ = os.MkdirAll(headDir, 0o755)
	_ = os.WriteFile(filepath.Join(baseDir, "a.go"), []byte("package a\n"), 0o644)
	_ = os.WriteFile(filepath.Join(headDir, "a.go"), []byte("package a\n"), 0o644)
	_ = os.WriteFile(filepath.Join(headDir, "head.txt"), []byte("1"), 0o644)

	exec := NewExecutor(Config{Mode: "container", Runtime: mockDocker, Image: "golang:1.26-trixie@sha256:" + strings.Repeat("b", 64)})

	// 1. Compile error must be classified as inconclusive, never reproduced.
	_ = os.WriteFile(stateFile, []byte("compile_error"), 0o644)
	compRep := exec.RunLab(context.Background(), LabSpec{
		BaseWorktree: baseDir,
		HeadWorktree: headDir,
		TestName:     "TestBug",
	})
	if compRep.Outcome != LabInconclusive || compRep.EvidenceState != evidence.StateInconclusive {
		t.Fatalf("expected inconclusive for compile error, got %+v", compRep)
	}

	// 2. Base pass + Head reproducible fail + candidate patch pass.
	_ = os.WriteFile(stateFile, []byte("normal"), 0o644)
	rep := exec.RunLab(context.Background(), LabSpec{
		BaseWorktree:   baseDir,
		HeadWorktree:   headDir,
		TestName:       "TestBug",
		RepeatCount:    2,
		CandidatePatch: map[string]string{"patched.txt": "fixed"},
	})
	if rep.Outcome != LabRegression || rep.EvidenceState != evidence.StateDifferentiallyReproduced {
		t.Fatalf("expected LabRegression + StateDifferentiallyReproduced, got %+v", rep)
	}
	if !rep.PatchVerified {
		t.Fatalf("expected PatchVerified=true, got %+v", rep)
	}
	if !strings.Contains(rep.FailureSignature, "FAIL: TestBug") {
		t.Fatalf("expected failure signature, got %q", rep.FailureSignature)
	}
}
