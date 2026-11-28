// Package semdiff provides a language-aware semantic diff engine that classifies
// structural, behavioral, API, serialization, auth, error-handling, and pure-refactoring
// changes mapped back to PR diff line numbers.
package semdiff

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/Eresus-Security-OSS/CodeSpider/internal/codeintel"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/lang"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/workspace"
)

// ChangeKind classifies the semantic nature of a code change.
type ChangeKind string

const (
	ChangeFuncAdded            ChangeKind = "func_added"
	ChangeFuncRemoved          ChangeKind = "func_removed"
	ChangeFuncRenamed          ChangeKind = "func_renamed"
	ChangeCodeMoved            ChangeKind = "code_moved"
	ChangeSignatureChanged     ChangeKind = "signature_changed"
	ChangeTypeChanged          ChangeKind = "type_changed"
	ChangeControlFlowChanged   ChangeKind = "control_flow_changed"
	ChangeErrorHandlingChanged ChangeKind = "error_handling_changed"
	ChangeAuthChanged          ChangeKind = "auth_changed"
	ChangePublicAPIChanged     ChangeKind = "public_api_changed"
	ChangeSerializationChanged ChangeKind = "serialization_changed"
	ChangeDBContractChanged    ChangeKind = "db_contract_changed"
	ChangeTestChanged          ChangeKind = "test_changed"
	ChangeEquivalentRefactor   ChangeKind = "equivalent_refactor"
	ChangeConfigOrDocs         ChangeKind = "config_or_docs"
)

// SemanticChange ties a classified behavioral or structural delta to its diff location.
type SemanticChange struct {
	Kind                   ChangeKind `json:"kind"`
	Language               string     `json:"language"`
	Path                   string     `json:"path"`
	OldPath                string     `json:"old_path,omitempty"`
	Symbol                 string     `json:"symbol,omitempty"`
	OldSymbol              string     `json:"old_symbol,omitempty"`
	DiffStartLine          int64      `json:"diff_start_line,omitempty"`
	DiffEndLine            int64      `json:"diff_end_line,omitempty"`
	Summary                string     `json:"summary"`
	Risk                   string     `json:"risk"` // low, medium, high
	BehaviorallyEquivalent bool       `json:"behaviorally_equivalent,omitempty"`
}

// DiffSummary aggregates all semantic changes and computes a pruned diff and focused LLM brief.
type DiffSummary struct {
	Changes              []SemanticChange `json:"changes"`
	HighRiskCount        int              `json:"high_risk_count"`
	OnlyEquivalentOrDocs bool             `json:"only_equivalent_or_docs"`
	FocusedBrief         string           `json:"focused_brief"`
	PrunedDiff           string           `json:"pruned_diff"`
}

// Input supplies base/head snapshots, worktree paths, and the raw unified diff.
type Input struct {
	BaseWorktree string
	HeadWorktree string
	BaseSnap     *codeintel.Snapshot
	HeadSnap     *codeintel.Snapshot
	Diff         string
	ChangedPaths []string
}

type goFuncASTInfo struct {
	Sym       codeintel.Symbol
	BodyHash  string
	ParamSig  string
	AuthCalls int
	ErrChecks int
	Branches  int
}

// Analyze computes semantic changes across Go ASTs, SQL/config/test files, and unified diff hunks.
func Analyze(in Input) DiffSummary {
	var changes []SemanticChange
	hunkLines := extractFirstDiffLines(in.Diff)

	if in.BaseSnap != nil && in.HeadSnap != nil {
		baseFuncs := extractGoFuncInfo(in.BaseWorktree, in.BaseSnap)
		headFuncs := extractGoFuncInfo(in.HeadWorktree, in.HeadSnap)
		changes = append(changes, diffGoSymbols(in.BaseSnap, in.HeadSnap, baseFuncs, headFuncs, hunkLines)...)
	}

	for _, p := range in.ChangedPaths {
		slash := filepath.ToSlash(p)
		lower := strings.ToLower(slash)
		line := hunkLines[slash]
		switch {
		case strings.HasSuffix(lower, ".sql"):
			changes = append(changes, SemanticChange{
				Kind:          ChangeDBContractChanged,
				Language:      "sql",
				Path:          slash,
				DiffStartLine: line,
				DiffEndLine:   line,
				Summary:       "Database migration or SQL contract modified",
				Risk:          "high",
			})
		case strings.HasSuffix(lower, "_test.go") || strings.Contains(lower, ".test.") || strings.Contains(lower, ".spec."):
			changes = append(changes, SemanticChange{
				Kind:          ChangeTestChanged,
				Language:      lang.DetectLanguage(slash),
				Path:          slash,
				DiffStartLine: line,
				DiffEndLine:   line,
				Summary:       "Test suite modified",
				Risk:          "low",
			})
		case strings.HasSuffix(lower, ".md") || strings.HasSuffix(lower, ".txt"):
			changes = append(changes, SemanticChange{
				Kind:                   ChangeConfigOrDocs,
				Language:               "docs",
				Path:                   slash,
				DiffStartLine:          line,
				DiffEndLine:            line,
				Summary:                "Documentation file updated",
				Risk:                   "low",
				BehaviorallyEquivalent: true,
			})
		}
	}

	// If no AST snapshot was available or for non-Go files, check diff hunks for comment-only edits.
	pruned := pruneTrivialHunks(in.Diff)
	if len(changes) == 0 && strings.TrimSpace(in.Diff) != "" && strings.TrimSpace(pruned) == "" {
		for _, p := range in.ChangedPaths {
			changes = append(changes, SemanticChange{
				Kind:                   ChangeEquivalentRefactor,
				Language:               lang.DetectLanguage(p),
				Path:                   filepath.ToSlash(p),
				DiffStartLine:          hunkLines[filepath.ToSlash(p)],
				Summary:                "Comments/whitespace-only formatting edit",
				Risk:                   "low",
				BehaviorallyEquivalent: true,
			})
		}
	}

	sort.Slice(changes, func(i, j int) bool {
		if changes[i].Path != changes[j].Path {
			return changes[i].Path < changes[j].Path
		}
		return changes[i].Symbol < changes[j].Symbol
	})

	highRisk := 0
	onlyEquiv := len(changes) > 0
	for _, c := range changes {
		if c.Risk == "high" {
			highRisk++
		}
		if !c.BehaviorallyEquivalent {
			onlyEquiv = false
		}
	}

	return DiffSummary{
		Changes:              changes,
		HighRiskCount:        highRisk,
		OnlyEquivalentOrDocs: onlyEquiv,
		FocusedBrief:         formatFocusedBrief(changes),
		PrunedDiff:           pruned,
	}
}

func diffGoSymbols(baseSnap, headSnap *codeintel.Snapshot, baseFuncs, headFuncs map[string]goFuncASTInfo, hunkLines map[string]int64) []SemanticChange {
	var changes []SemanticChange
	matchedRemoved := make(map[string]bool)
	matchedAdded := make(map[string]bool)

	var removedIDs, addedIDs []string
	for id, b := range baseFuncs {
		if _, ok := headFuncs[id]; !ok {
			removedIDs = append(removedIDs, id)
		} else {
			h := headFuncs[id]
			line := int64(h.Sym.StartLine)
			if dl, ok := hunkLines[h.Sym.File]; ok && dl > 0 {
				line = dl
			}
			if b.Sym.Signature != h.Sym.Signature {
				kind := ChangeSignatureChanged
				risk := "medium"
				if h.Sym.Exported || b.Sym.Exported {
					kind = ChangePublicAPIChanged
					risk = "high"
				}
				changes = append(changes, SemanticChange{
					Kind: kind, Language: "go", Path: h.Sym.File, Symbol: h.Sym.ID,
					DiffStartLine: line, DiffEndLine: int64(h.Sym.EndLine),
					Summary: fmt.Sprintf("Signature changed: %s -> %s", b.Sym.Signature, h.Sym.Signature),
					Risk:    risk,
				})
			} else if b.BodyHash == h.BodyHash && b.Sym.File != h.Sym.File {
				changes = append(changes, SemanticChange{
					Kind: ChangeCodeMoved, Language: "go", Path: h.Sym.File, OldPath: b.Sym.File, Symbol: h.Sym.ID,
					DiffStartLine: line, DiffEndLine: int64(h.Sym.EndLine),
					Summary:                fmt.Sprintf("Moved `%s` from `%s` to `%s` with identical AST", h.Sym.Name, b.Sym.File, h.Sym.File),
					Risk:                   "low",
					BehaviorallyEquivalent: true,
				})
			} else if b.BodyHash == h.BodyHash && fileInHunk(h.Sym.File, hunkLines) {
				changes = append(changes, SemanticChange{
					Kind: ChangeEquivalentRefactor, Language: "go", Path: h.Sym.File, Symbol: h.Sym.ID,
					DiffStartLine: line, DiffEndLine: int64(h.Sym.EndLine),
					Summary:                fmt.Sprintf("Behaviorally equivalent formatting/comment edit in `%s`", h.Sym.Name),
					Risk:                   "low",
					BehaviorallyEquivalent: true,
				})
			} else if b.BodyHash != h.BodyHash {
				switch {
				case b.AuthCalls != h.AuthCalls:
					changes = append(changes, SemanticChange{
						Kind: ChangeAuthChanged, Language: "go", Path: h.Sym.File, Symbol: h.Sym.ID,
						DiffStartLine: line, DiffEndLine: int64(h.Sym.EndLine),
						Summary: fmt.Sprintf("Authorization/signature guard calls changed in `%s` (%d -> %d)", h.Sym.Name, b.AuthCalls, h.AuthCalls),
						Risk:    "high",
					})
				case b.ErrChecks != h.ErrChecks:
					changes = append(changes, SemanticChange{
						Kind: ChangeErrorHandlingChanged, Language: "go", Path: h.Sym.File, Symbol: h.Sym.ID,
						DiffStartLine: line, DiffEndLine: int64(h.Sym.EndLine),
						Summary: fmt.Sprintf("Error handling checks changed in `%s` (%d -> %d)", h.Sym.Name, b.ErrChecks, h.ErrChecks),
						Risk:    "medium",
					})
				case b.Branches != h.Branches:
					changes = append(changes, SemanticChange{
						Kind: ChangeControlFlowChanged, Language: "go", Path: h.Sym.File, Symbol: h.Sym.ID,
						DiffStartLine: line, DiffEndLine: int64(h.Sym.EndLine),
						Summary: fmt.Sprintf("Control-flow branches changed in `%s` (%d -> %d)", h.Sym.Name, b.Branches, h.Branches),
						Risk:    "medium",
					})
				}
			}
		}
	}
	for id := range headFuncs {
		if _, ok := baseFuncs[id]; !ok {
			addedIDs = append(addedIDs, id)
		}
	}
	sort.Strings(removedIDs)
	sort.Strings(addedIDs)

	// Detect renames and moves via identical normalized AST body hash + parameter/return shape.
	for _, rID := range removedIDs {
		b := baseFuncs[rID]
		for _, aID := range addedIDs {
			if matchedAdded[aID] {
				continue
			}
			h := headFuncs[aID]
			if b.BodyHash != "" && b.BodyHash == h.BodyHash && b.ParamSig == h.ParamSig {
				matchedRemoved[rID] = true
				matchedAdded[aID] = true
				kind := ChangeFuncRenamed
				if b.Sym.File != h.Sym.File && b.Sym.Name == h.Sym.Name {
					kind = ChangeCodeMoved
				}
				changes = append(changes, SemanticChange{
					Kind: kind, Language: "go", Path: h.Sym.File, OldPath: b.Sym.File, Symbol: h.Sym.ID, OldSymbol: b.Sym.ID,
					DiffStartLine:          int64(h.Sym.StartLine),
					DiffEndLine:            int64(h.Sym.EndLine),
					Summary:                fmt.Sprintf("`%s` renamed/moved to `%s` with identical AST body", b.Sym.ID, h.Sym.ID),
					Risk:                   "low",
					BehaviorallyEquivalent: !b.Sym.Exported,
				})
				break
			}
		}
	}

	for _, rID := range removedIDs {
		if matchedRemoved[rID] {
			continue
		}
		b := baseFuncs[rID]
		risk := "medium"
		if b.Sym.Exported {
			risk = "high"
		}
		changes = append(changes, SemanticChange{
			Kind: ChangeFuncRemoved, Language: "go", Path: b.Sym.File, Symbol: b.Sym.ID,
			DiffStartLine: int64(b.Sym.StartLine), DiffEndLine: int64(b.Sym.EndLine),
			Summary: fmt.Sprintf("Removed function `%s`", b.Sym.ID),
			Risk:    risk,
		})
	}
	for _, aID := range addedIDs {
		if matchedAdded[aID] {
			continue
		}
		h := headFuncs[aID]
		kind := ChangeFuncAdded
		if strings.HasSuffix(h.Sym.File, "_test.go") {
			kind = ChangeTestChanged
		}
		changes = append(changes, SemanticChange{
			Kind: kind, Language: "go", Path: h.Sym.File, Symbol: h.Sym.ID,
			DiffStartLine: int64(h.Sym.StartLine), DiffEndLine: int64(h.Sym.EndLine),
			Summary: fmt.Sprintf("Added function `%s`", h.Sym.ID),
			Risk:    "low",
		})
	}

	// Detect struct JSON tag & interface type changes.
	for id, bSym := range baseSnap.Symbols {
		hSym, ok := headSnap.Symbols[id]
		if !ok {
			continue
		}
		if bSym.Kind == "struct" && !equalMaps(bSym.JSONTags, hSym.JSONTags) {
			changes = append(changes, SemanticChange{
				Kind: ChangeSerializationChanged, Language: "go", Path: hSym.File, Symbol: id,
				DiffStartLine: int64(hSym.StartLine), DiffEndLine: int64(hSym.EndLine),
				Summary: fmt.Sprintf("Struct `%s` JSON wire tags modified", bSym.Name),
				Risk:    "high",
			})
		}
		if bSym.Kind == "interface" && strings.Join(bSym.InterfaceMethods, ";") != strings.Join(hSym.InterfaceMethods, ";") {
			changes = append(changes, SemanticChange{
				Kind: ChangeTypeChanged, Language: "go", Path: hSym.File, Symbol: id,
				DiffStartLine: int64(hSym.StartLine), DiffEndLine: int64(hSym.EndLine),
				Summary: fmt.Sprintf("Interface `%s` method set modified", bSym.Name),
				Risk:    "high",
			})
		}
	}
	return changes
}

func extractGoFuncInfo(rootDir string, snap *codeintel.Snapshot) map[string]goFuncASTInfo {
	out := make(map[string]goFuncASTInfo)
	if snap == nil {
		return out
	}
	byFile := make(map[string][]codeintel.Symbol)
	for _, sym := range snap.Symbols {
		if sym.Kind == "func" || sym.Kind == "method" {
			byFile[sym.File] = append(byFile[sym.File], sym)
		}
	}
	fset := token.NewFileSet()
	for relFile, syms := range byFile {
		if rootDir == "" {
			for _, sym := range syms {
				out[sym.ID] = goFuncASTInfo{Sym: sym}
			}
			continue
		}
		raw, err := workspace.ReadSafeFile(rootDir, relFile, 2<<20)
		if err != nil {
			continue
		}
		af, err := parser.ParseFile(fset, relFile, raw, 0)
		if err != nil {
			continue
		}
		astByPos := make(map[int]*ast.FuncDecl)
		for _, decl := range af.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok {
				astByPos[fset.Position(fn.Pos()).Line] = fn
			}
		}
		for _, sym := range syms {
			info := goFuncASTInfo{Sym: sym}
			if _, after, ok := strings.Cut(sym.Signature, "("); ok {
				info.ParamSig = "(" + after
			}
			if fn, ok := astByPos[sym.StartLine]; ok && fn.Body != nil {
				var buf strings.Builder
				_ = printer.Fprint(&buf, fset, fn.Body)
				sum := sha256.Sum256([]byte(buf.String()))
				info.BodyHash = hex.EncodeToString(sum[:8])
				info.AuthCalls, info.ErrChecks, info.Branches = countFuncMetrics(fn.Body)
			}
			out[sym.ID] = info
		}
	}
	return out
}

func countFuncMetrics(body *ast.BlockStmt) (authCalls, errChecks, branches int) {
	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.IfStmt:
			branches++
			if be, ok := node.Cond.(*ast.BinaryExpr); ok {
				if id, ok := be.X.(*ast.Ident); ok && id.Name == "err" {
					errChecks++
				}
			}
		case *ast.SwitchStmt, *ast.TypeSwitchStmt, *ast.SelectStmt, *ast.ForStmt, *ast.RangeStmt:
			branches++
		case *ast.CallExpr:
			var name string
			switch fn := node.Fun.(type) {
			case *ast.Ident:
				name = fn.Name
			case *ast.SelectorExpr:
				name = fn.Sel.Name
			}
			lower := strings.ToLower(name)
			if strings.Contains(lower, "auth") || strings.Contains(lower, "verify") ||
				strings.Contains(lower, "permission") || strings.Contains(lower, "collaborator") ||
				strings.Contains(lower, "checktool") || strings.Contains(lower, "constanttime") {
				authCalls++
			}
		}
		return true
	})
	return authCalls, errChecks, branches
}

func pruneTrivialHunks(diff string) string {
	if strings.TrimSpace(diff) == "" {
		return ""
	}
	var kept []string
	var curFile strings.Builder
	hasBehavioral := false
	flush := func() {
		if hasBehavioral && curFile.Len() > 0 {
			kept = append(kept, curFile.String())
		}
		curFile.Reset()
		hasBehavioral = false
	}
	for _, line := range strings.Split(diff, "\n") {
		if strings.HasPrefix(line, "diff --git ") {
			flush()
			curFile.WriteString(line)
			curFile.WriteByte('\n')
			continue
		}
		curFile.WriteString(line)
		curFile.WriteByte('\n')
		if (strings.HasPrefix(line, "+") && !strings.HasPrefix(line, "+++")) ||
			(strings.HasPrefix(line, "-") && !strings.HasPrefix(line, "---")) {
			body := strings.TrimSpace(line[1:])
			if body != "" && !strings.HasPrefix(body, "//") && !strings.HasPrefix(body, "#") &&
				!strings.HasPrefix(body, "/*") && !strings.HasPrefix(body, "*") {
				hasBehavioral = true
			}
		}
	}
	flush()
	return strings.Join(kept, "")
}

func extractFirstDiffLines(diff string) map[string]int64 {
	out := make(map[string]int64)
	var cur string
	for _, line := range strings.Split(diff, "\n") {
		if strings.HasPrefix(line, "+++ b/") {
			cur = filepath.ToSlash(strings.TrimSpace(strings.TrimPrefix(line, "+++ b/")))
			continue
		}
		if cur != "" && strings.HasPrefix(line, "@@ ") {
			if _, after, ok := strings.Cut(line, "+"); ok {
				numPart, _, _ := strings.Cut(after, ",")
				numPart, _, _ = strings.Cut(numPart, " ")
				if n, err := strconv.ParseInt(strings.TrimSpace(numPart), 10, 64); err == nil {
					if _, exists := out[cur]; !exists {
						out[cur] = n
					}
				}
			}
		}
	}
	return out
}

func fileInHunk(path string, hunkLines map[string]int64) bool {
	_, ok := hunkLines[filepath.ToSlash(path)]
	return ok
}

func equalMaps(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

func formatFocusedBrief(changes []SemanticChange) string {
	if len(changes) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("## Semantic Change Summary\n")
	for i, c := range changes {
		if i >= 12 {
			fmt.Fprintf(&b, "- ... (%d more semantic changes)\n", len(changes)-12)
			break
		}
		fmt.Fprintf(&b, "- [%s/%s] %s (%s:%d)\n", strings.ToUpper(c.Risk), c.Kind, c.Summary, c.Path, c.DiffStartLine)
	}
	return b.String()
}
