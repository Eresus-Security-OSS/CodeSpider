package analysis

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"

	"github.com/Eresus-Security-OSS/CodeSpider/internal/evidence"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/workspace"
)

// CFGBlock represents a basic block in an intraprocedural Go control-flow graph.
type CFGBlock struct {
	ID         int
	Stmts      []ast.Stmt
	Succs      []*CFGBlock
	Terminates bool
}

// FuncCFG models basic blocks, entry/exit structure, and deferred cleanup calls for a Go function.
type FuncCFG struct {
	Name   string
	Entry  *CFGBlock
	Blocks []*CFGBlock
	Defers []string
}

func buildFuncCFG(fn *ast.FuncDecl) *FuncCFG {
	if fn == nil || fn.Body == nil {
		return nil
	}
	cfg := &FuncCFG{Name: fn.Name.Name}
	newBlock := func() *CFGBlock {
		b := &CFGBlock{ID: len(cfg.Blocks)}
		cfg.Blocks = append(cfg.Blocks, b)
		return b
	}
	cfg.Entry = newBlock()

	var walkStmts func(cur *CFGBlock, stmts []ast.Stmt) *CFGBlock
	walkStmts = func(cur *CFGBlock, stmts []ast.Stmt) *CFGBlock {
		for _, s := range stmts {
			if cur == nil || cur.Terminates {
				break
			}
			switch st := s.(type) {
			case *ast.DeferStmt:
				cfg.Defers = append(cfg.Defers, callTargetName(st.Call))
				cur.Stmts = append(cur.Stmts, s)
			case *ast.ReturnStmt:
				cur.Stmts = append(cur.Stmts, s)
				cur.Terminates = true
			case *ast.IfStmt:
				cur.Stmts = append(cur.Stmts, s)
				thenBlock := newBlock()
				cur.Succs = append(cur.Succs, thenBlock)
				thenEnd := walkStmts(thenBlock, st.Body.List)

				var elseEnd *CFGBlock
				if st.Else != nil {
					elseBlock := newBlock()
					cur.Succs = append(cur.Succs, elseBlock)
					switch eb := st.Else.(type) {
					case *ast.BlockStmt:
						elseEnd = walkStmts(elseBlock, eb.List)
					case *ast.IfStmt:
						elseEnd = walkStmts(elseBlock, []ast.Stmt{eb})
					}
				} else {
					elseEnd = newBlock()
					cur.Succs = append(cur.Succs, elseEnd)
				}

				join := newBlock()
				if thenEnd != nil && !thenEnd.Terminates {
					thenEnd.Succs = append(thenEnd.Succs, join)
				}
				if elseEnd != nil && !elseEnd.Terminates {
					elseEnd.Succs = append(elseEnd.Succs, join)
				}
				if len(join.Succs) == 0 && (thenEnd == nil || thenEnd.Terminates) && (elseEnd == nil || elseEnd.Terminates) {
					join.Terminates = true
				}
				cur = join
			case *ast.ForStmt:
				cur.Stmts = append(cur.Stmts, s)
				bodyBlock := newBlock()
				afterBlock := newBlock()
				cur.Succs = append(cur.Succs, bodyBlock, afterBlock)
				bodyEnd := walkStmts(bodyBlock, st.Body.List)
				if bodyEnd != nil && !bodyEnd.Terminates {
					bodyEnd.Succs = append(bodyEnd.Succs, bodyBlock, afterBlock)
				}
				cur = afterBlock
			case *ast.RangeStmt:
				cur.Stmts = append(cur.Stmts, s)
				bodyBlock := newBlock()
				afterBlock := newBlock()
				cur.Succs = append(cur.Succs, bodyBlock, afterBlock)
				bodyEnd := walkStmts(bodyBlock, st.Body.List)
				if bodyEnd != nil && !bodyEnd.Terminates {
					bodyEnd.Succs = append(bodyEnd.Succs, bodyBlock, afterBlock)
				}
				cur = afterBlock
			default:
				cur.Stmts = append(cur.Stmts, s)
			}
		}
		return cur
	}

	walkStmts(cfg.Entry, fn.Body.List)
	return cfg
}

// AnalyzeGoCFGAndDataFlow performs AST + CFG intraprocedural analysis on changed Go files
// to detect resource leaks, lock-without-unlock / lock-across-I/O, context leaks, and SQL tx rollback gaps.
func AnalyzeGoCFGAndDataFlow(headWorktree string, changedPaths []string, commitSHA string) []evidence.Finding {
	if headWorktree == "" || len(changedPaths) == 0 {
		return nil
	}
	var findings []evidence.Finding
	fset := token.NewFileSet()

	for _, rel := range changedPaths {
		slash := filepath.ToSlash(rel)
		if !strings.HasSuffix(slash, ".go") || strings.HasSuffix(slash, "_test.go") {
			continue
		}
		raw, err := workspace.ReadSafeFile(headWorktree, slash, 2<<20)
		if err != nil {
			continue
		}
		file, err := parser.ParseFile(fset, slash, raw, 0)
		if err != nil {
			continue
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			cfg := buildFuncCFG(fn)
			findings = append(findings, checkResourceLeaks(fset, slash, fn, cfg, commitSHA)...)
			findings = append(findings, checkMutexSafety(fset, slash, fn, cfg, commitSHA)...)
			findings = append(findings, checkContextAndTxSafety(fset, slash, fn, cfg, commitSHA)...)
		}
	}
	return findings
}

func checkResourceLeaks(fset *token.FileSet, file string, fn *ast.FuncDecl, cfg *FuncCFG, sha string) []evidence.Finding {
	var out []evidence.Finding
	var respVars []struct {
		name string
		line int64
	}
	closed := make(map[string]bool)

	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.AssignStmt:
			if len(node.Rhs) == 1 && len(node.Lhs) >= 1 {
				if ce, ok := node.Rhs[0].(*ast.CallExpr); ok {
					callee := callTargetName(ce)
					if callee == "http.Get" || callee == "http.Post" || callee == "http.Head" ||
						strings.HasSuffix(callee, ".Do") || callee == "os.Open" {
						if id, ok := node.Lhs[0].(*ast.Ident); ok && id.Name != "_" {
							respVars = append(respVars, struct {
								name string
								line int64
							}{name: id.Name, line: int64(fset.Position(node.Pos()).Line)})
						}
					}
				}
			}
		case *ast.CallExpr:
			callee := callTargetName(node)
			if strings.HasSuffix(callee, ".Body.Close") || strings.HasSuffix(callee, ".Close") {
				root := strings.Split(callee, ".")[0]
				closed[root] = true
			}
		}
		return true
	})

	for _, rv := range respVars {
		if !closed[rv.name] {
			out = append(out, makeStaticSecFinding("CS-FLOW-001", "resource-leak", "warning", file, rv.line, fn.Name.Name+"."+rv.name, sha,
				"HTTP response or file handle never closed",
				fmt.Sprintf("Resource `%s` acquired in `%s` has no matching `defer %s.Body.Close()` / `Close()` on CFG exit paths.", rv.name, fn.Name.Name, rv.name),
				"CFG/AST check found acquisition without Close() in "+fn.Name.Name))
		}
	}
	return out
}

func checkMutexSafety(fset *token.FileSet, file string, fn *ast.FuncDecl, cfg *FuncCFG, sha string) []evidence.Finding {
	var out []evidence.Finding
	var lockLine int64
	var lockTarget string
	hasDeferUnlock := false
	hasEarlyReturnWithoutUnlock := false
	hasIOWithLock := false

	for _, d := range cfg.Defers {
		if strings.HasSuffix(d, ".Unlock") || strings.HasSuffix(d, ".RUnlock") {
			hasDeferUnlock = true
		}
	}

	// Walk blocks linearly in entry order to detect Lock -> Return (without defer/Unlock) and Lock -> I/O.
	locked := false
	for _, blk := range cfg.Blocks {
		unlockedInBlock := false
		for _, st := range blk.Stmts {
			ast.Inspect(st, func(n ast.Node) bool {
				ce, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				callee := callTargetName(ce)
				switch {
				case strings.HasSuffix(callee, ".Lock") || strings.HasSuffix(callee, ".RLock"):
					locked = true
					lockLine = int64(fset.Position(ce.Pos()).Line)
					lockTarget = callee
				case strings.HasSuffix(callee, ".Unlock") || strings.HasSuffix(callee, ".RUnlock"):
					locked = false
					unlockedInBlock = true
				case locked && (strings.HasPrefix(callee, "http.") || strings.Contains(callee, ".Query") ||
					strings.Contains(callee, ".Exec") || strings.HasPrefix(callee, "exec.Command")):
					hasIOWithLock = true
				}
				return true
			})
			if _, isRet := st.(*ast.ReturnStmt); isRet && locked && !hasDeferUnlock && !unlockedInBlock {
				hasEarlyReturnWithoutUnlock = true
			}
		}
	}

	if hasEarlyReturnWithoutUnlock && lockLine > 0 {
		out = append(out, makeStaticSecFinding("CS-FLOW-002", "concurrency", "critical", file, lockLine, fn.Name.Name+".unlock", sha,
			"Mutex locked without defer Unlock on return path",
			fmt.Sprintf("`%s` in `%s` can return while lock `%s` is still held (no `defer` unlock), risking deadlock.", fn.Name.Name, lockTarget, lockTarget),
			"CFG path from Lock() to ReturnStmt without Unlock() or defer Unlock()"))
	} else if hasIOWithLock && lockLine > 0 {
		out = append(out, makeStaticSecFinding("CS-FLOW-002", "concurrency", "warning", file, lockLine, fn.Name.Name+".lock_io", sha,
			"Mutex held across blocking I/O or subprocess call",
			fmt.Sprintf("Lock `%s` in `%s` appears held while performing network, database, or subprocess I/O.", lockTarget, fn.Name.Name),
			"CFG block contains I/O call while lock state is active"))
	}
	return out
}

func checkContextAndTxSafety(fset *token.FileSet, file string, fn *ast.FuncDecl, cfg *FuncCFG, sha string) []evidence.Finding {
	var out []evidence.Finding
	var cancelVar string
	var cancelLine int64
	cancelCalled := false

	var txVar string
	var txLine int64
	txRolledBack := false

	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.AssignStmt:
			if len(node.Rhs) == 1 {
				if ce, ok := node.Rhs[0].(*ast.CallExpr); ok {
					callee := callTargetName(ce)
					if (callee == "context.WithCancel" || callee == "context.WithTimeout" || callee == "context.WithDeadline") && len(node.Lhs) >= 2 {
						if id, ok := node.Lhs[1].(*ast.Ident); ok {
							cancelLine = int64(fset.Position(node.Pos()).Line)
							cancelVar = id.Name
						}
					}
					if (strings.HasSuffix(callee, ".Begin") || strings.HasSuffix(callee, ".BeginTx")) && len(node.Lhs) >= 1 {
						if id, ok := node.Lhs[0].(*ast.Ident); ok && id.Name != "_" {
							txLine = int64(fset.Position(node.Pos()).Line)
							txVar = id.Name
						}
					}
				}
			}
		case *ast.CallExpr:
			callee := callTargetName(node)
			if cancelVar != "" && cancelVar != "_" && callee == cancelVar {
				cancelCalled = true
			}
			if txVar != "" && (callee == txVar+".Rollback" || callee == txVar+".Commit") {
				if callee == txVar+".Rollback" {
					txRolledBack = true
				}
			}
		}
		return true
	})

	if cancelLine > 0 && (cancelVar == "_" || !cancelCalled) {
		out = append(out, makeStaticSecFinding("CS-FLOW-003", "resource-leak", "warning", file, cancelLine, fn.Name.Name+".cancel", sha,
			"Context cancel function discarded or never called",
			fmt.Sprintf("`context.With*` in `%s` does not call/defer its cancel function, leaking timer/goroutine resources until parent context expires.", fn.Name.Name),
			"AST check found context.With* without cancel invocation"))
	}
	if txLine > 0 && !txRolledBack {
		out = append(out, makeStaticSecFinding("CS-FLOW-004", "database-safety", "warning", file, txLine, fn.Name.Name+".tx", sha,
			"SQL transaction started without Rollback safeguard",
			fmt.Sprintf("Transaction `%s` in `%s` has no `defer %s.Rollback()` / `Rollback()` path, risking leaked locks on error/panic.", txVar, fn.Name.Name, txVar),
			"AST check found Begin/BeginTx without Rollback()"))
	}
	return out
}

func callTargetName(ce *ast.CallExpr) string {
	if ce == nil {
		return ""
	}
	switch fn := ce.Fun.(type) {
	case *ast.Ident:
		return fn.Name
	case *ast.SelectorExpr:
		return exprString(fn.X) + "." + fn.Sel.Name
	default:
		return ""
	}
}

func exprString(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.Ident:
		return v.Name
	case *ast.SelectorExpr:
		return exprString(v.X) + "." + v.Sel.Name
	case *ast.CallExpr:
		return callTargetName(v)
	default:
		return ""
	}
}
