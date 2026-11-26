package lang

import (
	"bytes"
	"context"
	"encoding/json"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/Eresus-Security-OSS/CodeSpider/internal/workspace"
)

const pythonASTCaps = CapSyntax | CapSymbols | CapImports | CapCalls | CapSemanticDiff | CapContracts | CapTests
const pythonFallbackCaps = CapSymbols | CapImports | CapTests

const pythonASTHelper = `
import ast, json, sys

src = sys.stdin.read()
try:
    tree = ast.parse(src)
except SyntaxError as e:
    print(json.dumps({"parse_error": f"line {e.lineno}: {e.msg}"}))
    sys.exit(0)

imports = []
symbols = []
contracts = []
tests = []

def unparse(node):
    if node is None:
        return ""
    try:
        return ast.unparse(node)
    except Exception:
        return ""

for node in ast.walk(tree):
    if isinstance(node, ast.Import):
        for alias in node.names:
            imports.append(alias.name)
    elif isinstance(node, ast.ImportFrom):
        mod = node.module or ""
        for alias in node.names:
            imports.append(f"{mod}.{alias.name}" if mod else alias.name)

def extract_calls(fn_node):
    calls = []
    for sub in ast.walk(fn_node):
        if isinstance(sub, ast.Call):
            c = unparse(sub.func)
            if c and c not in calls:
                calls.append(c)
    return calls[:30]

for node in tree.body:
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        args = [a.arg + (": " + unparse(a.annotation) if a.annotation else "") for a in node.args.args]
        ret = (" -> " + unparse(node.returns)) if node.returns else ""
        prefix = "async def " if isinstance(node, ast.AsyncFunctionDef) else "def "
        sig = f"{prefix}{node.name}({', '.join(args)}){ret}"
        decs = [unparse(d) for d in node.decorator_list]
        is_test = node.name.startswith("test_")
        if is_test:
            tests.append(node.name)
        exported = not node.name.startswith("_")
        symbols.append({
            "id": node.name,
            "name": node.name,
            "kind": "test" if is_test else "func",
            "start_line": node.lineno,
            "end_line": getattr(node, "end_lineno", node.lineno),
            "exported": exported,
            "signature": sig,
            "calls": extract_calls(node),
            "decorators": decs,
            "is_test": is_test,
        })
        for d in decs:
            if any(k in d for k in ("route(", ".get(", ".post(", ".put(", ".delete(", ".patch(")):
                contracts.append({"kind": "http_route", "name": node.name, "line": node.lineno, "signature": f"@{d} {sig}"})
        if exported and not is_test:
            contracts.append({"kind": "function", "name": node.name, "line": node.lineno, "signature": sig})
    elif isinstance(node, ast.ClassDef):
        symbols.append({
            "id": node.name,
            "name": node.name,
            "kind": "class",
            "start_line": node.lineno,
            "end_line": getattr(node, "end_lineno", node.lineno),
            "exported": not node.name.startswith("_"),
            "signature": f"class {node.name}",
            "decorators": [unparse(d) for d in node.decorator_list],
        })

print(json.dumps({"imports": sorted(set(imports)), "symbols": symbols, "contracts": contracts, "tests": tests}))
`

// PythonAnalyzer inspects Python source files using an isolated `python3 -I -S` AST subprocess
// (never executing untrusted repository code), with a structural regex fallback when python3 is absent.
type PythonAnalyzer struct {
	pythonBin string
}

// NewPythonAnalyzer probes for python3 in PATH and configures isolated AST inspection.
func NewPythonAnalyzer() *PythonAnalyzer {
	bin, _ := exec.LookPath("python3")
	return &PythonAnalyzer{pythonBin: bin}
}

func (a *PythonAnalyzer) Language() string { return "python" }
func (a *PythonAnalyzer) Version() string  { return InterfaceVersion }

func (a *PythonAnalyzer) Status() AnalyzerStatus {
	if a.pythonBin != "" {
		return AnalyzerStatus{
			Language:     "python",
			Version:      InterfaceVersion,
			Adapter:      "isolated python3 -I -S ast.parse subprocess",
			Available:    true,
			Capabilities: CapabilityNames(pythonASTCaps),
			Limitations:  "Syntactic AST + type annotations only; dynamic runtime attributes, monkey-patching, and full cross-module type inference are not modeled.",
		}
	}
	return AnalyzerStatus{
		Language:     "python",
		Version:      InterfaceVersion,
		Adapter:      "structural fallback (python3 not found)",
		Available:    true,
		Capabilities: CapabilityNames(pythonFallbackCaps),
		Limitations:  "python3 binary unavailable; falling back to top-level def/class/import scanning without AST call extraction.",
	}
}

func (a *PythonAnalyzer) SupportsFile(relPath string) bool {
	return strings.EqualFold(filepath.Ext(relPath), ".py")
}

func (a *PythonAnalyzer) AnalyzeFiles(ctx context.Context, rootDir string, relPaths []string) ([]FileAnalysis, error) {
	out := make([]FileAnalysis, 0, len(relPaths))
	for _, rel := range relPaths {
		raw, err := workspace.ReadSafeFile(rootDir, rel, 1<<20)
		if err != nil {
			out = append(out, FileAnalysis{Language: "python", File: rel, ParseError: err.Error()})
			continue
		}
		if a.pythonBin != "" {
			if fa, ok := a.analyzeWithPythonAST(ctx, rel, raw); ok {
				out = append(out, fa)
				continue
			}
		}
		out = append(out, analyzePythonFallback(rel, string(raw)))
	}
	return out, nil
}

func (a *PythonAnalyzer) analyzeWithPythonAST(ctx context.Context, rel string, raw []byte) (FileAnalysis, bool) {
	runCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(runCtx, a.pythonBin, "-I", "-S", "-c", pythonASTHelper)
	cmd.Stdin = bytes.NewReader(raw)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return FileAnalysis{}, false
	}
	var parsed struct {
		ParseError string     `json:"parse_error"`
		Imports    []string   `json:"imports"`
		Symbols    []Symbol   `json:"symbols"`
		Contracts  []Contract `json:"contracts"`
		Tests      []string   `json:"tests"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &parsed); err != nil {
		return FileAnalysis{}, false
	}
	for i := range parsed.Symbols {
		parsed.Symbols[i].File = rel
	}
	for i := range parsed.Contracts {
		parsed.Contracts[i].File = rel
	}
	return FileAnalysis{
		Language:     "python",
		File:         rel,
		Capabilities: pythonASTCaps,
		ParseError:   parsed.ParseError,
		Imports:      parsed.Imports,
		Symbols:      parsed.Symbols,
		Contracts:    parsed.Contracts,
		Tests:        parsed.Tests,
	}, true
}

var (
	pyDefRe    = regexp.MustCompile(`^(?:async\s+)?def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)`)
	pyClassRe  = regexp.MustCompile(`^class\s+([A-Za-z_][A-Za-z0-9_]*)`)
	pyImportRe = regexp.MustCompile(`^(?:from\s+([A-Za-z0-9_.]+)\s+import|import\s+([A-Za-z0-9_.]+))`)
)

func analyzePythonFallback(rel, src string) FileAnalysis {
	fa := FileAnalysis{Language: "python", File: rel, Capabilities: pythonFallbackCaps}
	for idx, line := range strings.Split(src, "\n") {
		lineNo := idx + 1
		if m := pyImportRe.FindStringSubmatch(strings.TrimSpace(line)); m != nil {
			mod := m[1]
			if mod == "" {
				mod = m[2]
			}
			fa.Imports = append(fa.Imports, mod)
		} else if m := pyDefRe.FindStringSubmatch(line); m != nil {
			name := m[1]
			isTest := strings.HasPrefix(name, "test_")
			fa.Symbols = append(fa.Symbols, Symbol{
				ID:        name,
				Name:      name,
				Kind:      "func",
				File:      rel,
				StartLine: lineNo,
				EndLine:   lineNo,
				Exported:  !strings.HasPrefix(name, "_"),
				Signature: strings.TrimSpace(strings.TrimSuffix(line, ":")),
				IsTest:    isTest,
			})
			if isTest {
				fa.Tests = append(fa.Tests, name)
			}
		} else if m := pyClassRe.FindStringSubmatch(line); m != nil {
			fa.Symbols = append(fa.Symbols, Symbol{
				ID:        m[1],
				Name:      m[1],
				Kind:      "class",
				File:      rel,
				StartLine: lineNo,
				EndLine:   lineNo,
				Exported:  !strings.HasPrefix(m[1], "_"),
				Signature: "class " + m[1],
			})
		}
	}
	return fa
}
