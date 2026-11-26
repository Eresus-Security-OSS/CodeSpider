package sandbox

import (
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"

	"github.com/Eresus-Security-OSS/CodeSpider/internal/evidence"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/workspace"
)

// LabOutcome classifies the full differential Proof-of-Bug pipeline result.
type LabOutcome string

const (
	LabRegression    LabOutcome = "differentially_reproduced"
	LabPreExisting   LabOutcome = "pre_existing_failure"
	LabNotReproduced LabOutcome = "not_reproduced"
	LabFlaky         LabOutcome = "flaky_inconclusive"
	LabInconclusive  LabOutcome = "inconclusive"
	LabPatchVerified LabOutcome = "patch_verified"
)

// LabSpec configures a differential reproduction and optional candidate-patch verification run.
type LabSpec struct {
	BaseWorktree   string
	HeadWorktree   string
	PackageDir     string
	TestName       string
	TestCode       string
	RepeatCount    int               // default 2 when verifying regressions for flake detection
	CandidatePatch map[string]string // optional relative path -> replacement file content
}

// LabReport captures the structured evidence produced by the Proof-of-Bug laboratory.
type LabReport struct {
	Outcome          LabOutcome     `json:"outcome"`
	EvidenceState    evidence.State `json:"evidence_state"`
	FailureSignature string         `json:"failure_signature,omitempty"`
	BaseResult       Result         `json:"base_result"`
	HeadResult       Result         `json:"head_result"`
	RepeatResult     *Result        `json:"repeat_result,omitempty"`
	PatchResult      *Result        `json:"patch_result,omitempty"`
	PatchVerified    bool           `json:"patch_verified,omitempty"`
	Notes            []string       `json:"notes,omitempty"`
}

var blockedPoCImports = map[string]bool{
	"os/exec":  true,
	"syscall":  true,
	"unsafe":   true,
	"plugin":   true,
	"net":      true,
	"net/http": true,
}

// ValidatePoCTestSource parses generated Go PoC test source and blocks unsafe imports or missing test functions.
func ValidatePoCTestSource(testName, src string) error {
	if !validTestNameRe.MatchString(testName) {
		return fmt.Errorf("invalid test_name %q", testName)
	}
	if strings.TrimSpace(src) == "" {
		return nil
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "codespider_poc_test.go", src, 0)
	if err != nil {
		return fmt.Errorf("invalid PoC Go syntax: %w", err)
	}
	for _, imp := range file.Imports {
		p := strings.Trim(imp.Path.Value, `"`)
		if blockedPoCImports[p] {
			return fmt.Errorf("PoC test import %q is prohibited", p)
		}
	}
	hasTest := false
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name.Name == testName {
			hasTest = true
			break
		}
	}
	if !hasTest {
		return fmt.Errorf("PoC test source does not define func %s", testName)
	}
	return nil
}

// RunLab executes the full Proof-of-Bug differential pipeline:
// PoC validation -> head run -> compile/env error check -> base run -> flake repeat -> candidate patch check.
func (e *Executor) RunLab(ctx context.Context, spec LabSpec) LabReport {
	rep := LabReport{Outcome: LabInconclusive, EvidenceState: evidence.StateInconclusive}
	if err := ValidatePoCTestSource(spec.TestName, spec.TestCode); err != nil {
		rep.Notes = append(rep.Notes, err.Error())
		return rep
	}

	pkgDir := spec.PackageDir
	if strings.TrimSpace(pkgDir) == "" {
		pkgDir = "."
	}

	headRes := e.RunGoTest(ctx, spec.HeadWorktree, pkgDir, spec.TestName, spec.TestCode)
	rep.HeadResult = headRes
	if headRes.Status == StatusUnavailable || headRes.Status == StatusError {
		rep.Notes = append(rep.Notes, "head execution unavailable or timed out")
		return rep
	}
	if isCompileOrSetupFailure(headRes.Output) {
		rep.Notes = append(rep.Notes, "head test failed to compile or resolve environment; marked inconclusive")
		return rep
	}
	if headRes.Status == StatusPassed {
		rep.Outcome = LabNotReproduced
		rep.Notes = append(rep.Notes, "test passed on head commit")
		return rep
	}

	rep.FailureSignature = extractFailureSignature(headRes.Output)

	if strings.TrimSpace(spec.BaseWorktree) == "" {
		rep.Notes = append(rep.Notes, "base worktree unavailable for differential comparison")
		return rep
	}
	baseRes := e.RunGoTest(ctx, spec.BaseWorktree, pkgDir, spec.TestName, spec.TestCode)
	rep.BaseResult = baseRes
	if baseRes.Status == StatusUnavailable || baseRes.Status == StatusError || isCompileOrSetupFailure(baseRes.Output) {
		rep.Notes = append(rep.Notes, "base execution inconclusive")
		return rep
	}
	if baseRes.Status == StatusFailed {
		rep.Outcome = LabPreExisting
		rep.EvidenceState = evidence.StateTestReproduced
		rep.Notes = append(rep.Notes, "test failed on both base and head commits (pre-existing)")
		return rep
	}

	// Flake check: repeat head test when RepeatCount >= 2 (default 2).
	repeats := spec.RepeatCount
	if repeats == 0 {
		repeats = 2
	}
	if repeats >= 2 {
		repRes := e.RunGoTest(ctx, spec.HeadWorktree, pkgDir, spec.TestName, spec.TestCode)
		rep.RepeatResult = &repRes
		if repRes.Status != StatusFailed {
			rep.Outcome = LabFlaky
			rep.EvidenceState = evidence.StateInconclusive
			rep.Notes = append(rep.Notes, "head failure did not reproduce consistently on repeat run (flaky)")
			return rep
		}
	}

	rep.Outcome = LabRegression
	rep.EvidenceState = evidence.StateDifferentiallyReproduced
	rep.Notes = append(rep.Notes, "base passed and head reproducibly failed")

	// Optional candidate patch verification in a separate disposable workspace copy.
	if len(spec.CandidatePatch) > 0 {
		patchedDir, err := os.MkdirTemp("", "codespider-patch-*")
		if err == nil {
			defer os.RemoveAll(patchedDir)
			if copyErr := copyWorkspaceWithoutGit(spec.HeadWorktree, patchedDir); copyErr == nil {
				applyOK := true
				for rel, content := range spec.CandidatePatch {
					if wErr := workspace.WriteSafeFile(patchedDir, rel, []byte(content)); wErr != nil {
						applyOK = false
						rep.Notes = append(rep.Notes, fmt.Sprintf("candidate patch write error (%s): %v", rel, wErr))
						break
					}
				}
				if applyOK {
					patchRes := e.RunGoTest(ctx, patchedDir, pkgDir, spec.TestName, spec.TestCode)
					rep.PatchResult = &patchRes
					if patchRes.Status == StatusPassed {
						rep.PatchVerified = true
						rep.Notes = append(rep.Notes, "candidate patch eliminated failure in isolated sandbox")
					}
				}
			}
		}
	}

	return rep
}

func isCompileOrSetupFailure(output string) bool {
	lower := strings.ToLower(output)
	return strings.Contains(lower, "[build failed]") ||
		strings.Contains(lower, "[setup failed]") ||
		strings.Contains(lower, "cannot find package") ||
		strings.Contains(lower, "undefined:") ||
		strings.Contains(lower, "syntax error:")
}

func extractFailureSignature(output string) string {
	for _, line := range strings.Split(output, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "panic:") ||
			strings.HasPrefix(trimmed, "WARNING: DATA RACE") ||
			strings.HasPrefix(trimmed, "--- FAIL:") ||
			strings.Contains(trimmed, "_test.go:") {
			if len(trimmed) > 160 {
				return trimmed[:160]
			}
			return trimmed
		}
	}
	return "test_failed"
}
