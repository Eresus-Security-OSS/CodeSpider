// Package codeintel provides deterministic Go AST/type indexing, content-addressed caching,
// import/call graphs, and commit-aware snapshots using only the Go standard library.
package codeintel

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"go/ast"
	"go/build/constraint"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// Symbol represents an exported or unexported Go declaration extracted from AST.
type Symbol struct {
	ID               string            `json:"id"`
	Name             string            `json:"name"`
	Kind             string            `json:"kind"` // func, method, struct, interface, type, alias
	Receiver         string            `json:"receiver,omitempty"`
	PkgPath          string            `json:"pkg_path"`
	File             string            `json:"file"`
	StartLine        int               `json:"start_line"`
	EndLine          int               `json:"end_line"`
	Exported         bool              `json:"exported"`
	IsAlias          bool              `json:"is_alias,omitempty"`
	TypeParams       []string          `json:"type_params,omitempty"`
	InterfaceMethods []string          `json:"interface_methods,omitempty"`
	Signature        string            `json:"signature"`
	JSONTags         map[string]string `json:"json_tags,omitempty"`
	Calls            []string          `json:"calls,omitempty"`
	TakesContext     bool              `json:"takes_context,omitempty"`
	ReturnsError     bool              `json:"returns_error,omitempty"`
}

// PackageSummary captures symbols and imports for a single Go package directory.
type PackageSummary struct {
	PkgPath              string
	Dir                  string
	Files                []string
	SkippedBuildTagFiles []string
	Imports              []string
	UnresolvedImports    []string
	Symbols              []Symbol
	TypeSafe             bool
	TypeErrors           []string
}

// Snapshot is a commit-aware deterministic index of a Go repository worktree.
type Snapshot struct {
	CommitSHA      string
	ModulePath     string
	Packages       map[string]*PackageSummary
	Symbols        map[string]Symbol
	ImportGraph    map[string][]string
	CallGraph      map[string][]string
	ReverseCallers map[string][]string
}

type cachedFile struct {
	imports []string
	symbols []Symbol
	astFile *ast.File
}

// Indexer builds Snapshot instances with a thread-safe content-addressed SHA-256 AST cache.
type Indexer struct {
	mu        sync.RWMutex
	fset      *token.FileSet
	fileCache map[[32]byte]cachedFile
}

// NewIndexer creates a new content-addressed Go code Indexer.
func NewIndexer() *Indexer {
	return &Indexer{
		fset:      token.NewFileSet(),
		fileCache: make(map[[32]byte]cachedFile),
	}
}

// CacheLen returns the number of cached file AST entries (useful for incremental caching tests).
func (idx *Indexer) CacheLen() int {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	return len(idx.fileCache)
}

// IndexWorktree scans all Go packages in rootDir (excluding .git, vendor, node_modules).
func (idx *Indexer) IndexWorktree(rootDir, commitSHA string) (*Snapshot, error) {
	if rootDir == "" {
		return nil, fmt.Errorf("rootDir is required")
	}
	snap := &Snapshot{
		CommitSHA:      commitSHA,
		ModulePath:     readGoModulePath(rootDir),
		Packages:       make(map[string]*PackageSummary),
		Symbols:        make(map[string]Symbol),
		ImportGraph:    make(map[string][]string),
		CallGraph:      make(map[string][]string),
		ReverseCallers: make(map[string][]string),
	}

	pkgFiles := make(map[string][]string)
	_ = filepath.WalkDir(rootDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if d.Name() == ".git" || d.Name() == "vendor" || d.Name() == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(d.Name(), ".go") {
			return nil
		}
		rel, relErr := filepath.Rel(rootDir, path)
		if relErr != nil {
			return nil
		}
		relSlash := filepath.ToSlash(rel)
		pkgDir := filepath.ToSlash(filepath.Dir(relSlash))
		pkgFiles[pkgDir] = append(pkgFiles[pkgDir], relSlash)
		return nil
	})

	for pkgDir, files := range pkgFiles {
		sort.Strings(files)
		ps := &PackageSummary{
			PkgPath: pkgDir,
			Dir:     pkgDir,
			Files:   files,
		}
		importSet := make(map[string]struct{})
		var parsedFiles []*ast.File

		for _, relFile := range files {
			full := filepath.Join(rootDir, filepath.FromSlash(relFile))
			raw, readErr := os.ReadFile(full)
			if readErr != nil {
				continue
			}
			if !shouldIncludeGoFile(raw) {
				ps.SkippedBuildTagFiles = append(ps.SkippedBuildTagFiles, relFile)
				continue
			}
			cf, ok := idx.parseCached(relFile, pkgDir, raw)
			if !ok {
				continue
			}
			for _, imp := range cf.imports {
				importSet[imp] = struct{}{}
			}
			ps.Symbols = append(ps.Symbols, cf.symbols...)
			if cf.astFile != nil {
				parsedFiles = append(parsedFiles, cf.astFile)
			}
		}

		for imp := range importSet {
			ps.Imports = append(ps.Imports, imp)
		}
		sort.Strings(ps.Imports)
		snap.ImportGraph[pkgDir] = ps.Imports

		// Attempt go/types type-checking (stdlib + unresolved import tracking).
		if len(parsedFiles) > 0 {
			defaultImp := importer.Default()
			unresolvedSet := make(map[string]struct{})
			conf := types.Config{
				Importer: importerFunc(func(path string) (*types.Package, error) {
					pkg, err := defaultImp.Import(path)
					if err != nil {
						unresolvedSet[path] = struct{}{}
					}
					return pkg, err
				}),
				Error: func(err error) {
					ps.TypeErrors = append(ps.TypeErrors, err.Error())
				},
			}
			if _, typeErr := conf.Check(pkgDir, idx.fset, parsedFiles, nil); typeErr == nil {
				ps.TypeSafe = true
			}
			for u := range unresolvedSet {
				ps.UnresolvedImports = append(ps.UnresolvedImports, u)
			}
			sort.Strings(ps.UnresolvedImports)
		}

		for _, sym := range ps.Symbols {
			snap.Symbols[sym.ID] = sym
		}
		snap.Packages[pkgDir] = ps
	}

	buildCallGraphs(snap)
	return snap, nil
}

func (idx *Indexer) parseCached(relFile, pkgDir string, raw []byte) (cachedFile, bool) {
	sum := sha256.Sum256(raw)
	idx.mu.RLock()
	if cf, ok := idx.fileCache[sum]; ok {
		idx.mu.RUnlock()
		// Rebind file/pkg metadata if identical bytes exist at another path.
		out := cf
		out.symbols = make([]Symbol, len(cf.symbols))
		copy(out.symbols, cf.symbols)
		for i := range out.symbols {
			out.symbols[i].File = relFile
			out.symbols[i].PkgPath = pkgDir
			out.symbols[i].ID = symbolID(pkgDir, out.symbols[i].Receiver, out.symbols[i].Name)
		}
		return out, true
	}
	idx.mu.RUnlock()

	file, err := parser.ParseFile(idx.fset, relFile, raw, 0)
	if err != nil {
		return cachedFile{}, false
	}

	var imports []string
	for _, imp := range file.Imports {
		imports = append(imports, strings.Trim(imp.Path.Value, `"`))
	}

	var syms []Symbol
	for _, decl := range file.Decls {
		switch d := decl.(type) {
		case *ast.GenDecl:
			for _, spec := range d.Specs {
				if ts, ok := spec.(*ast.TypeSpec); ok {
					syms = append(syms, extractTypeSymbol(idx.fset, pkgDir, relFile, ts, raw))
				}
			}
		case *ast.FuncDecl:
			syms = append(syms, extractFuncSymbol(idx.fset, pkgDir, relFile, d, raw))
		}
	}

	cf := cachedFile{
		imports: imports,
		symbols: syms,
		astFile: file,
	}
	idx.mu.Lock()
	idx.fileCache[sum] = cf
	idx.mu.Unlock()
	return cf, true
}

func extractTypeSymbol(fset *token.FileSet, pkgDir, relFile string, ts *ast.TypeSpec, raw []byte) Symbol {
	kind := "type"
	isAlias := ts.Assign.IsValid()
	if isAlias {
		kind = "alias"
	}
	jsonTags := make(map[string]string)
	var ifaceMethods []string
	switch t := ts.Type.(type) {
	case *ast.StructType:
		kind = "struct"
		if t.Fields != nil {
			for _, f := range t.Fields.List {
				if f.Tag == nil {
					continue
				}
				tag := parseJSONTag(f.Tag.Value)
				if tag == "" {
					continue
				}
				for _, n := range f.Names {
					jsonTags[n.Name] = tag
				}
			}
		}
	case *ast.InterfaceType:
		kind = "interface"
		if t.Methods != nil {
			for _, m := range t.Methods.List {
				if len(m.Names) == 0 {
					ifaceMethods = append(ifaceMethods, exprText(m.Type, raw, fset))
					continue
				}
				sig := exprText(m.Type, raw, fset)
				for _, n := range m.Names {
					ifaceMethods = append(ifaceMethods, n.Name+strings.TrimPrefix(sig, "func"))
				}
			}
			sort.Strings(ifaceMethods)
		}
	}
	tparams := extractTypeParams(ts.TypeParams, raw, fset)
	sig := kind + " " + ts.Name.Name
	if len(tparams) > 0 {
		sig += "[" + strings.Join(tparams, ", ") + "]"
	}
	if isAlias {
		sig = "type " + ts.Name.Name + " = " + exprText(ts.Type, raw, fset)
	}
	start := fset.Position(ts.Pos()).Line
	end := fset.Position(ts.End()).Line
	return Symbol{
		ID:               symbolID(pkgDir, "", ts.Name.Name),
		Name:             ts.Name.Name,
		Kind:             kind,
		PkgPath:          pkgDir,
		File:             relFile,
		StartLine:        start,
		EndLine:          end,
		Exported:         ast.IsExported(ts.Name.Name),
		IsAlias:          isAlias,
		TypeParams:       tparams,
		InterfaceMethods: ifaceMethods,
		Signature:        sig,
		JSONTags:         jsonTags,
	}
}

func extractFuncSymbol(fset *token.FileSet, pkgDir, relFile string, fn *ast.FuncDecl, raw []byte) Symbol {
	recv := ""
	kind := "func"
	if fn.Recv != nil && len(fn.Recv.List) > 0 {
		kind = "method"
		recv = exprText(fn.Recv.List[0].Type, raw, fset)
	}
	takesCtx := false
	if fn.Type.Params != nil && len(fn.Type.Params.List) > 0 {
		firstType := exprText(fn.Type.Params.List[0].Type, raw, fset)
		if strings.Contains(firstType, "context.Context") {
			takesCtx = true
		}
	}
	returnsErr := false
	if fn.Type.Results != nil {
		for _, res := range fn.Type.Results.List {
			if exprText(res.Type, raw, fset) == "error" {
				returnsErr = true
			}
		}
	}

	var calls []string
	if fn.Body != nil {
		seenCalls := make(map[string]struct{})
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			ce, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			var callee string
			switch fun := ce.Fun.(type) {
			case *ast.Ident:
				callee = fun.Name
			case *ast.SelectorExpr:
				callee = exprText(fun.X, raw, fset) + "." + fun.Sel.Name
			}
			if callee != "" {
				if _, exists := seenCalls[callee]; !exists {
					seenCalls[callee] = struct{}{}
					calls = append(calls, callee)
				}
			}
			return true
		})
	}
	sort.Strings(calls)

	tparams := extractTypeParams(fn.Type.TypeParams, raw, fset)
	start := fset.Position(fn.Pos()).Line
	end := fset.Position(fn.End()).Line
	return Symbol{
		ID:           symbolID(pkgDir, recv, fn.Name.Name),
		Name:         fn.Name.Name,
		Kind:         kind,
		Receiver:     recv,
		PkgPath:      pkgDir,
		File:         relFile,
		StartLine:    start,
		EndLine:      end,
		Exported:     ast.IsExported(fn.Name.Name),
		TypeParams:   tparams,
		Signature:    formatFuncSignature(fn, recv, tparams, raw, fset),
		Calls:        calls,
		TakesContext: takesCtx,
		ReturnsError: returnsErr,
	}
}

func formatFuncSignature(fn *ast.FuncDecl, recv string, tparams []string, raw []byte, fset *token.FileSet) string {
	var b bytes.Buffer
	b.WriteString("func ")
	if recv != "" {
		fmt.Fprintf(&b, "(%s) ", recv)
	}
	b.WriteString(fn.Name.Name)
	if len(tparams) > 0 {
		b.WriteByte('[')
		b.WriteString(strings.Join(tparams, ", "))
		b.WriteByte(']')
	}
	b.WriteByte('(')
	if fn.Type.Params != nil {
		var parts []string
		for _, p := range fn.Type.Params.List {
			typ := exprText(p.Type, raw, fset)
			if len(p.Names) == 0 {
				parts = append(parts, typ)
			} else {
				for range p.Names {
					parts = append(parts, typ)
				}
			}
		}
		b.WriteString(strings.Join(parts, ", "))
	}
	b.WriteByte(')')
	if fn.Type.Results != nil && len(fn.Type.Results.List) > 0 {
		var res []string
		for _, r := range fn.Type.Results.List {
			typ := exprText(r.Type, raw, fset)
			if len(r.Names) == 0 {
				res = append(res, typ)
			} else {
				for range r.Names {
					res = append(res, typ)
				}
			}
		}
		if len(res) == 1 {
			b.WriteByte(' ')
			b.WriteString(res[0])
		} else {
			fmt.Fprintf(&b, " (%s)", strings.Join(res, ", "))
		}
	}
	return b.String()
}

func exprText(expr ast.Expr, raw []byte, fset *token.FileSet) string {
	start := fset.Position(expr.Pos()).Offset
	end := fset.Position(expr.End()).Offset
	if start >= 0 && end <= len(raw) && start < end {
		return strings.Join(strings.Fields(string(raw[start:end])), " ")
	}
	return ""
}

func parseJSONTag(rawTag string) string {
	trimmed := strings.Trim(rawTag, "`")
	idx := strings.Index(trimmed, `json:"`)
	if idx == -1 {
		return ""
	}
	rest := trimmed[idx+6:]
	end := strings.IndexByte(rest, '"')
	if end == -1 {
		return ""
	}
	name, _, _ := strings.Cut(rest[:end], ",")
	return name
}

func symbolID(pkgDir, recv, name string) string {
	cleanRecv := strings.TrimPrefix(recv, "*")
	if cleanRecv != "" {
		return pkgDir + "." + cleanRecv + "." + name
	}
	return pkgDir + "." + name
}

type importerFunc func(path string) (*types.Package, error)

func (f importerFunc) Import(path string) (*types.Package, error) { return f(path) }

func extractTypeParams(fl *ast.FieldList, raw []byte, fset *token.FileSet) []string {
	if fl == nil || len(fl.List) == 0 {
		return nil
	}
	var out []string
	for _, field := range fl.List {
		typ := exprText(field.Type, raw, fset)
		if len(field.Names) == 0 {
			out = append(out, typ)
			continue
		}
		for _, n := range field.Names {
			out = append(out, n.Name+" "+typ)
		}
	}
	return out
}

func shouldIncludeGoFile(raw []byte) bool {
	lines := strings.Split(string(raw), "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "package ") {
			break
		}
		if constraint.IsGoBuild(trimmed) {
			expr, err := constraint.Parse(trimmed)
			if err != nil {
				return true
			}
			okLinux := expr.Eval(func(tag string) bool {
				return tag == "linux" || tag == "unix" || tag == "amd64" || tag == "gc" || tag == "go1.26"
			})
			okDarwin := expr.Eval(func(tag string) bool {
				return tag == "darwin" || tag == "unix" || tag == "arm64" || tag == "gc" || tag == "go1.26"
			})
			return okLinux || okDarwin
		}
	}
	return true
}

func readGoModulePath(rootDir string) string {
	raw, err := os.ReadFile(filepath.Join(rootDir, "go.mod"))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(raw), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "module ") {
			return strings.TrimSpace(strings.TrimPrefix(trimmed, "module "))
		}
	}
	return ""
}
