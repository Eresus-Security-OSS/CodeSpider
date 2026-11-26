package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Eresus-Security-OSS/CodeSpider/internal/lang"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/sandbox"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/workspace"
)

func (r *Registry) registerAdvancedTools(p Params) {
	if p.Workspace != nil && (p.Permissions == nil || p.Permissions.AllowSameOwner || len(p.Permissions.AllowedCrossRepo) > 0) {
		r.register("search_org_repos",
			"Search across permitted cached repository mirrors in the organization to detect cross-repo API, schema, or symbol blast radius.",
			schema(map[string]any{
				"pattern": prop("string", "Search regex pattern (e.g. function or endpoint name)"),
			}, []string{"pattern"}),
			func(ctx context.Context, raw string) (string, error) {
				var args struct {
					Pattern string `json:"pattern"`
				}
				if err := json.Unmarshal([]byte(raw), &args); err != nil {
					return "", err
				}
				exclude := ""
				if p.Trigger.Owner != "" && p.Trigger.Repo != "" {
					exclude = p.Trigger.Owner + "/" + p.Trigger.Repo
				}
				var allowedOwners, allowedRepos []string
				if p.Permissions != nil {
					if p.Permissions.AllowSameOwner && p.Permissions.Owner != "" {
						allowedOwners = append(allowedOwners, p.Permissions.Owner)
					}
					allowedRepos = append(allowedRepos, p.Permissions.AllowedCrossRepo...)
				}
				return p.Workspace.SearchCachedMirrorsWithAllowlist(ctx, exclude, args.Pattern, allowedOwners, allowedRepos, 40)
			},
		)
	}

	r.register("git_forensics",
		"Inspect git commit history for a file or line range, highlighting prior bugfix, security, or revert commits to catch regressions.",
		schema(map[string]any{
			"path":       prop("string", "Relative path inside repository"),
			"start_line": prop("integer", "Optional 1-based start line"),
			"end_line":   prop("integer", "Optional 1-based end line"),
		}, []string{"path"}),
		func(ctx context.Context, raw string) (string, error) {
			var args struct {
				Path      string `json:"path"`
				StartLine int    `json:"start_line"`
				EndLine   int    `json:"end_line"`
			}
			if err := json.Unmarshal([]byte(raw), &args); err != nil {
				return "", err
			}
			if p.Workspace == nil || p.WorktreeDir == "" {
				return "", fmt.Errorf("worktree not available")
			}
			return p.Workspace.FileForensics(ctx, p.WorktreeDir, args.Path, args.StartLine, args.EndLine)
		},
	)

	r.register("inspect_go_symbols",
		"Parse a Go source file AST and list its package, imports, types, and functions/methods with exact line ranges.",
		schema(map[string]any{
			"path": prop("string", "Relative path to a .go file inside repository"),
		}, []string{"path"}),
		func(ctx context.Context, raw string) (string, error) {
			var args struct {
				Path string `json:"path"`
			}
			if err := json.Unmarshal([]byte(raw), &args); err != nil {
				return "", err
			}
			if p.WorktreeDir == "" {
				return "", fmt.Errorf("worktree not available")
			}
			full, err := workspace.ResolveSafePath(p.WorktreeDir, args.Path)
			if err != nil {
				return "", err
			}
			return inspectGoFile(full)
		},
	)

	r.register("inspect_symbols",
		"Inspect symbols, imports, contracts, and test definitions for Go, Python, TypeScript/JavaScript, or Rust files.",
		schema(map[string]any{
			"path": prop("string", "Relative path to source file inside repository"),
		}, []string{"path"}),
		func(ctx context.Context, raw string) (string, error) {
			var args struct {
				Path string `json:"path"`
			}
			if err := json.Unmarshal([]byte(raw), &args); err != nil {
				return "", err
			}
			if p.WorktreeDir == "" {
				return "", fmt.Errorf("worktree not available")
			}
			reg := lang.NewDefaultRegistry()
			res, err := reg.AnalyzeFiles(ctx, p.WorktreeDir, []string{args.Path})
			if err != nil {
				return "", err
			}
			b, _ := json.MarshalIndent(res, "", "  ")
			return string(b), nil
		},
	)

	r.register("get_ci_status",
		"Fetch combined CI / commit status checks for the pull request head commit from Gitea.",
		schema(map[string]any{}, nil),
		func(ctx context.Context, raw string) (string, error) {
			if p.Gitea == nil || p.Trigger.HeadSHA == "" {
				return "no CI status available", nil
			}
			cs, err := p.Gitea.GetCombinedCommitStatus(ctx, p.Trigger.Owner, p.Trigger.Repo, p.Trigger.HeadSHA)
			if err != nil {
				return "", err
			}
			var b strings.Builder
			fmt.Fprintf(&b, "Combined state: %s\n", cs.State)
			for _, st := range cs.Statuses {
				fmt.Fprintf(&b, "- [%s] %s: %s\n", st.Status, st.Context, st.Description)
			}
			if len(cs.Statuses) == 0 {
				b.WriteString("(no individual status checks reported)\n")
			}
			return b.String(), nil
		},
	)

	if p.EnableProofOfBug && p.Sandbox != nil && p.Sandbox.Enabled() {
		r.register("run_proof_test",
			"Run an isolated container-sandboxed `go test -race` differential test against base and head worktrees.",
			schema(map[string]any{
				"package_dir": prop("string", "Relative Go package directory (default '.')"),
				"test_name":   prop("string", "Exact Go test function name (e.g. TestRaceOrPanic)"),
				"test_code":   prop("string", "Optional temporary _test.go source code to execute inside container"),
			}, []string{"test_name"}),
			func(ctx context.Context, raw string) (string, error) {
				var args struct {
					PackageDir string `json:"package_dir"`
					TestName   string `json:"test_name"`
					TestCode   string `json:"test_code"`
				}
				if err := json.Unmarshal([]byte(raw), &args); err != nil {
					return "", err
				}
				if args.PackageDir == "" {
					args.PackageDir = "."
				}
				if p.BaseWorktreeDir != "" {
					rep := p.Sandbox.RunLab(ctx, sandbox.LabSpec{
						BaseWorktree: p.BaseWorktreeDir,
						HeadWorktree: p.WorktreeDir,
						PackageDir:   args.PackageDir,
						TestName:     args.TestName,
						TestCode:     args.TestCode,
						RepeatCount:  2,
					})
					return fmt.Sprintf("DIFFERENTIAL OUTCOME: %s (state=%s sig=%s)\nHEAD:\n%s\nBASE:\n%s",
						rep.Outcome, rep.EvidenceState, rep.FailureSignature, rep.HeadResult.Output, rep.BaseResult.Output), nil
				}
				res := p.Sandbox.RunGoTest(ctx, p.WorktreeDir, args.PackageDir, args.TestName, args.TestCode)
				if res.Status == sandbox.StatusUnavailable {
					return "INCONCLUSIVE: " + res.Output, nil
				}
				return fmt.Sprintf("SANDBOX STATUS (%s):\n%s", res.Status, res.Output), nil
			},
		)
	}
}

// ParseDiffValidLines extracts 1-based new-file line numbers present inside unified diff hunks.
func ParseDiffValidLines(diff string) map[string]map[int64]bool {
	valid := make(map[string]map[int64]bool)
	if diff == "" {
		return valid
	}
	var currentFile string
	var newLine int64
	inHunk := false

	for _, line := range strings.Split(diff, "\n") {
		if strings.HasPrefix(line, "diff --git ") {
			inHunk = false
			currentFile = ""
			continue
		}
		if strings.HasPrefix(line, "+++ b/") {
			currentFile = filepath.ToSlash(strings.TrimSpace(strings.TrimPrefix(line, "+++ b/")))
			if valid[currentFile] == nil {
				valid[currentFile] = make(map[int64]bool)
			}
			continue
		}
		if m := hunkHeaderRe.FindStringSubmatch(line); m != nil {
			n, err := strconv.ParseInt(m[1], 10, 64)
			if err == nil {
				newLine = n
				inHunk = true
			}
			continue
		}
		if !inHunk || currentFile == "" {
			continue
		}
		switch {
		case strings.HasPrefix(line, "+++ ") || strings.HasPrefix(line, "--- ") || strings.HasPrefix(line, "\\"):
			continue
		case strings.HasPrefix(line, "+"), strings.HasPrefix(line, " "):
			valid[currentFile][newLine] = true
			newLine++
		}
	}
	return valid
}

func isLineInDiff(valid map[string]map[int64]bool, path string, line int64) bool {
	if len(valid) == 0 {
		return true
	}
	clean := filepath.ToSlash(filepath.Clean(path))
	lines, ok := valid[clean]
	if !ok {
		return false
	}
	return lines[line]
}

func inspectGoFile(fullPath string) (string, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, fullPath, nil, 0)
	if err != nil {
		return "", fmt.Errorf("parse go file: %w", err)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "package %s\n", file.Name.Name)
	if len(file.Imports) > 0 {
		b.WriteString("imports:\n")
		for _, imp := range file.Imports {
			fmt.Fprintf(&b, "  %s\n", imp.Path.Value)
		}
	}
	for _, decl := range file.Decls {
		switch d := decl.(type) {
		case *ast.GenDecl:
			for _, spec := range d.Specs {
				if ts, ok := spec.(*ast.TypeSpec); ok {
					start := fset.Position(ts.Pos()).Line
					end := fset.Position(ts.End()).Line
					fmt.Fprintf(&b, "type %s (L%d-L%d)\n", ts.Name.Name, start, end)
				}
			}
		case *ast.FuncDecl:
			start := fset.Position(d.Pos()).Line
			end := fset.Position(d.End()).Line
			if d.Recv != nil && len(d.Recv.List) > 0 {
				fmt.Fprintf(&b, "method %s (L%d-L%d)\n", d.Name.Name, start, end)
			} else {
				fmt.Fprintf(&b, "func %s (L%d-L%d)\n", d.Name.Name, start, end)
			}
		}
	}
	return b.String(), nil
}
