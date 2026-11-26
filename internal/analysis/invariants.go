package analysis

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/Eresus-Security-OSS/CodeSpider/internal/evidence"
)

var (
	guardTokenRe   = regexp.MustCompile(`\b(VerifySignature|hmac\.Equal|ConstantTimeCompare|IsCollaborator|ResolveSafePath|CheckToolAllowed)\b`)
	shellExecRe    = regexp.MustCompile(`exec\.Command(?:Context)?\([^)]*(?:"sh"|"/bin/sh"|"bash"|"/bin/bash")`)
	weakCryptoRe   = regexp.MustCompile(`"(crypto/md5|crypto/sha1|math/rand)"`)
	unboundedRead  = regexp.MustCompile(`io\.ReadAll\(\s*resp\.Body\s*\)`)
	sqlConcatRe    = regexp.MustCompile(`(?i)\b(?:Query|Exec|QueryRow)(?:Context)?\s*\([^)]*(?:fmt\.Sprintf|\+)`)
	diffHunkLineRe = regexp.MustCompile(`^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@`)
)

// AnalyzeSecurityInvariants checks the PR diff for removed security guards and unsafe Go/API sinks,
// ignoring comment lines to avoid false positives.
func AnalyzeSecurityInvariants(diff, commitSHA string) []evidence.Finding {
	return AnalyzeSecurityInvariantsAST("", "", diff, commitSHA)
}

// AnalyzeSecurityInvariantsAST uses Go AST comparison when base/head worktrees are available
// so comments and string literals never trigger security guard or sink false positives.
func AnalyzeSecurityInvariantsAST(baseWorktree, headWorktree, diff, commitSHA string) []evidence.Finding {
	if strings.TrimSpace(diff) == "" {
		return nil
	}
	var findings []evidence.Finding
	astCheckedFiles := make(map[string]bool)

	// When both worktrees exist, run real AST comparison on changed Go files first.
	if baseWorktree != "" && headWorktree != "" {
		changedLines := extractAddedLinesByFile(diff)
		for file, addedSet := range changedLines {
			if !strings.HasSuffix(file, ".go") {
				continue
			}
			basePath := filepath.Join(baseWorktree, filepath.FromSlash(file))
			headPath := filepath.Join(headWorktree, filepath.FromSlash(file))
			baseGuards, baseOK := extractGoGuardCalls(basePath)
			headGuards, headOK, headFindings := inspectGoHeadSecurityAST(headPath, file, addedSet, commitSHA)
			if baseOK && headOK {
				astCheckedFiles[file] = true
				for g, lineNo := range baseGuards {
					if headGuards[g] == 0 {
						findings = append(findings, makeStaticSecFinding("CS-INV-001", "security-invariant", "critical", file, lineNo, g, commitSHA,
							"Security guard removed", fmt.Sprintf("Security check `%s` was removed from `%s` without an equivalent replacement in the same file.", g, file),
							fmt.Sprintf("AST call %s present in base and absent in head", g)))
					}
				}
				findings = append(findings, headFindings...)
			}
		}
	}

	var currentFile string
	var newLine int64
	inHunk := false
	removedGuards := make(map[string]map[string]int64)
	addedGuards := make(map[string]map[string]bool)

	for _, line := range strings.Split(diff, "\n") {
		if strings.HasPrefix(line, "diff --git ") {
			inHunk = false
			currentFile = ""
			continue
		}
		if strings.HasPrefix(line, "+++ b/") {
			currentFile = filepath.ToSlash(strings.TrimSpace(strings.TrimPrefix(line, "+++ b/")))
			continue
		}
		if m := diffHunkLineRe.FindStringSubmatch(line); m != nil {
			if n, err := strconv.ParseInt(m[1], 10, 64); err == nil {
				newLine = n
				inHunk = true
			}
			continue
		}
		if !inHunk || currentFile == "" || astCheckedFiles[currentFile] {
			continue
		}
		if strings.HasPrefix(line, "-") && !strings.HasPrefix(line, "---") {
			codeLine := stripCommentLine(line[1:])
			if m := guardTokenRe.FindString(codeLine); m != "" {
				if removedGuards[currentFile] == nil {
					removedGuards[currentFile] = make(map[string]int64)
				}
				removedGuards[currentFile][m] = newLine
			}
			continue
		}
		if strings.HasPrefix(line, " ") {
			newLine++
			continue
		}
		if strings.HasPrefix(line, "+") && !strings.HasPrefix(line, "+++") {
			added := stripCommentLine(line[1:])
			if m := guardTokenRe.FindString(added); m != "" {
				if addedGuards[currentFile] == nil {
					addedGuards[currentFile] = make(map[string]bool)
				}
				addedGuards[currentFile][m] = true
			}
			if !strings.HasSuffix(currentFile, "_test.go") && strings.HasSuffix(currentFile, ".go") {
				if shellExecRe.MatchString(added) {
					findings = append(findings, makeStaticSecFinding("CS-SEC-001", "security", "critical", currentFile, newLine, "shell_exec", commitSHA,
						"Shell invocation via exec.Command", "Avoid invoking a shell (`sh`/`bash`) with `exec.Command`; pass binary and arguments directly to prevent command injection.",
						"matched shell execution pattern in added line"))
				}
				if sqlConcatRe.MatchString(added) {
					findings = append(findings, makeStaticSecFinding("CS-SEC-002", "security", "critical", currentFile, newLine, "sql_concat", commitSHA,
						"Potential SQL query string formatting/concatenation", "SQL query appears constructed via string concatenation or `fmt.Sprintf`; use parameterized placeholders instead.",
						"matched Query/Exec with fmt.Sprintf or '+' concatenation"))
				}
				if unboundedRead.MatchString(added) {
					findings = append(findings, makeStaticSecFinding("CS-SEC-003", "security", "warning", currentFile, newLine, "unbounded_read", commitSHA,
						"Unbounded HTTP response body read", "Wrap `resp.Body` with `io.LimitReader(resp.Body, maxBytes)` to prevent memory exhaustion.",
						"matched io.ReadAll(resp.Body) without LimitReader"))
				}
				if m := weakCryptoRe.FindStringSubmatch(added); len(m) == 2 {
					findings = append(findings, makeStaticSecFinding("CS-SEC-004", "security", "warning", currentFile, newLine, m[1], commitSHA,
						"Weak cryptographic or PRNG import", fmt.Sprintf("Imported `%s`; verify it is not used for signatures, password hashing, or security tokens.", m[1]),
						"added import "+m[1]))
				}
			}
			newLine++
		}
	}

	for file, guards := range removedGuards {
		for guard, lineNo := range guards {
			if addedGuards[file] != nil && addedGuards[file][guard] {
				continue
			}
			findings = append(findings, makeStaticSecFinding("CS-INV-001", "security-invariant", "critical", file, lineNo, guard, commitSHA,
				"Security guard removed", fmt.Sprintf("Security check `%s` was removed from `%s` without an equivalent replacement in the same file.", guard, file),
				fmt.Sprintf("security symbol %s present in removed lines and absent in added lines", guard)))
		}
	}

	return findings
}

func extractGoGuardCalls(fullPath string) (map[string]int64, bool) {
	raw, err := os.ReadFile(fullPath)
	if err != nil {
		return nil, false
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, fullPath, raw, 0)
	if err != nil {
		return nil, false
	}
	guards := make(map[string]int64)
	ast.Inspect(file, func(n ast.Node) bool {
		ce, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		name := callTargetName(ce)
		if guardTokenRe.MatchString(name) {
			guards[guardTokenRe.FindString(name)] = int64(fset.Position(ce.Pos()).Line)
		}
		return true
	})
	return guards, true
}

func inspectGoHeadSecurityAST(fullPath, relFile string, addedLines map[int64]bool, sha string) (map[string]int64, bool, []evidence.Finding) {
	guards, ok := extractGoGuardCalls(fullPath)
	if !ok {
		return nil, false, nil
	}
	if strings.HasSuffix(relFile, "_test.go") {
		return guards, true, nil
	}
	raw, err := os.ReadFile(fullPath)
	if err != nil {
		return guards, true, nil
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, fullPath, raw, 0)
	if err != nil {
		return guards, true, nil
	}

	var findings []evidence.Finding
	for _, imp := range file.Imports {
		line := int64(fset.Position(imp.Pos()).Line)
		if len(addedLines) > 0 && !addedLines[line] {
			continue
		}
		p := strings.Trim(imp.Path.Value, `"`)
		if p == "crypto/md5" || p == "crypto/sha1" || p == "math/rand" {
			findings = append(findings, makeStaticSecFinding("CS-SEC-004", "security", "warning", relFile, line, p, sha,
				"Weak cryptographic or PRNG import", fmt.Sprintf("Imported `%s`; verify it is not used for signatures, password hashing, or security tokens.", p),
				"AST import "+p))
		}
	}

	ast.Inspect(file, func(n ast.Node) bool {
		ce, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		line := int64(fset.Position(ce.Pos()).Line)
		if len(addedLines) > 0 && !addedLines[line] {
			return true
		}
		callee := callTargetName(ce)
		switch {
		case (callee == "exec.Command" || callee == "exec.CommandContext") && isShellCommandCall(ce):
			findings = append(findings, makeStaticSecFinding("CS-SEC-001", "security", "critical", relFile, line, "shell_exec", sha,
				"Shell invocation via exec.Command", "Avoid invoking a shell (`sh`/`bash`) with `exec.Command`; pass binary and arguments directly.",
				"AST exec.Command shell call"))
		case (strings.HasSuffix(callee, ".Query") || strings.HasSuffix(callee, ".QueryContext") ||
			strings.HasSuffix(callee, ".Exec") || strings.HasSuffix(callee, ".ExecContext") ||
			strings.HasSuffix(callee, ".QueryRow") || strings.HasSuffix(callee, ".QueryRowContext")) && hasDynamicSQLArg(ce):
			findings = append(findings, makeStaticSecFinding("CS-SEC-002", "security", "critical", relFile, line, "sql_concat", sha,
				"Potential SQL query string formatting/concatenation", "SQL query constructed dynamically via `fmt.Sprintf` or string concatenation; use parameterized placeholders.",
				"AST dynamic SQL argument"))
		case callee == "io.ReadAll" && len(ce.Args) == 1 && strings.HasSuffix(exprString(ce.Args[0]), ".Body"):
			findings = append(findings, makeStaticSecFinding("CS-SEC-003", "security", "warning", relFile, line, "unbounded_read", sha,
				"Unbounded HTTP response body read", "Wrap `resp.Body` with `io.LimitReader(resp.Body, maxBytes)` to prevent memory exhaustion.",
				"AST io.ReadAll(resp.Body)"))
		}
		return true
	})

	return guards, true, findings
}

func isShellCommandCall(ce *ast.CallExpr) bool {
	for _, arg := range ce.Args {
		if lit, ok := arg.(*ast.BasicLit); ok {
			val := strings.Trim(lit.Value, `"`)
			if val == "sh" || val == "/bin/sh" || val == "bash" || val == "/bin/bash" {
				return true
			}
		}
	}
	return false
}

func hasDynamicSQLArg(ce *ast.CallExpr) bool {
	for _, arg := range ce.Args {
		if be, ok := arg.(*ast.BinaryExpr); ok && be.Op == token.ADD {
			return true
		}
		if inner, ok := arg.(*ast.CallExpr); ok && callTargetName(inner) == "fmt.Sprintf" {
			return true
		}
	}
	return false
}

func extractAddedLinesByFile(diff string) map[string]map[int64]bool {
	out := make(map[string]map[int64]bool)
	var cur string
	var newLine int64
	inHunk := false
	for _, line := range strings.Split(diff, "\n") {
		if strings.HasPrefix(line, "diff --git ") {
			inHunk = false
			cur = ""
		} else if strings.HasPrefix(line, "+++ b/") {
			cur = filepath.ToSlash(strings.TrimSpace(strings.TrimPrefix(line, "+++ b/")))
			if out[cur] == nil {
				out[cur] = make(map[int64]bool)
			}
		} else if m := diffHunkLineRe.FindStringSubmatch(line); m != nil {
			if n, err := strconv.ParseInt(m[1], 10, 64); err == nil {
				newLine = n
				inHunk = true
			}
		} else if inHunk && cur != "" {
			if strings.HasPrefix(line, " ") {
				newLine++
			} else if strings.HasPrefix(line, "+") && !strings.HasPrefix(line, "+++") {
				out[cur][newLine] = true
				newLine++
			}
		}
	}
	return out
}

func stripCommentLine(s string) string {
	trimmed := strings.TrimSpace(s)
	if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "--") || strings.HasPrefix(trimmed, "/*") {
		return ""
	}
	return s
}

func makeStaticSecFinding(ruleID, category, sev, file string, line int64, symbol, sha, title, body, ev string) evidence.Finding {
	f := evidence.Finding{
		RuleID:    ruleID,
		Category:  category,
		Severity:  sev,
		State:     evidence.StateStaticallySupported,
		Path:      file,
		StartLine: line,
		EndLine:   line,
		Symbol:    symbol,
		CommitSHA: sha,
		Title:     title,
		Body:      body,
		Evidence:  []string{ev},
	}
	f.Fingerprint = evidence.ComputeFingerprint(f.RuleID, f.Category, f.Path, f.Symbol)
	return f
}
