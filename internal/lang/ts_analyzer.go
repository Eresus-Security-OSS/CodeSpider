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

const tsCompilerCaps = CapSyntax | CapSymbols | CapImports | CapCalls | CapSemanticDiff | CapContracts | CapTests
const tsStructuralCaps = CapSymbols | CapImports | CapContracts | CapTests

const tsASTHelper = `
const ts = require("typescript");
const fs = require("fs");
const file = process.argv[1] || "input.ts";
const src = fs.readFileSync(0, "utf8");
const sf = ts.createSourceFile(file, src, ts.ScriptTarget.Latest, true);
const imports = [];
const symbols = [];
const contracts = [];
const tests = [];

function lineOf(pos) { return sf.getLineAndCharacterOfPosition(pos).line + 1; }
function hasExport(node) {
  return !!(node.modifiers && node.modifiers.some(m => m.kind === ts.SyntaxKind.ExportKeyword));
}
function collectCalls(node) {
  const calls = new Set();
  function walk(n) {
    if (ts.isCallExpression(n)) {
      calls.add(n.expression.getText(sf));
    }
    ts.forEachChild(n, walk);
  }
  walk(node);
  return Array.from(calls).slice(0, 30);
}

sf.forEachChild(node => {
  if (ts.isImportDeclaration(node) && node.moduleSpecifier && ts.isStringLiteral(node.moduleSpecifier)) {
    imports.push(node.moduleSpecifier.text);
  } else if (ts.isFunctionDeclaration(node) && node.name) {
    const name = node.name.text;
    const exp = hasExport(node);
    const sig = node.getText(sf).split("{")[0].trim();
    symbols.push({ id: name, name, kind: "func", start_line: lineOf(node.getStart(sf)), end_line: lineOf(node.getEnd()), exported: exp, signature: sig, calls: collectCalls(node) });
    if (exp) contracts.push({ kind: "function", name, line: lineOf(node.getStart(sf)), signature: sig });
  } else if (ts.isInterfaceDeclaration(node) || ts.isTypeAliasDeclaration(node)) {
    const name = node.name.text;
    const exp = hasExport(node);
    const sig = node.getText(sf).split("\n")[0].trim();
    symbols.push({ id: name, name, kind: ts.isInterfaceDeclaration(node) ? "interface" : "type", start_line: lineOf(node.getStart(sf)), end_line: lineOf(node.getEnd()), exported: exp, signature: sig });
    if (exp) contracts.push({ kind: "type", name, line: lineOf(node.getStart(sf)), signature: sig });
  } else if (ts.isClassDeclaration(node) && node.name) {
    const name = node.name.text;
    const exp = hasExport(node);
    symbols.push({ id: name, name, kind: "class", start_line: lineOf(node.getStart(sf)), end_line: lineOf(node.getEnd()), exported: exp, signature: "class " + name });
  } else if (ts.isExpressionStatement(node) && ts.isCallExpression(node.expression)) {
    const fn = node.expression.expression.getText(sf);
    if ((fn === "test" || fn === "it" || fn === "describe") && node.expression.arguments.length > 0 && ts.isStringLiteral(node.expression.arguments[0])) {
      tests.push(node.expression.arguments[0].text);
    }
  }
});
console.log(JSON.stringify({ imports, symbols, contracts, tests }));
`

// TSAnalyzer analyzes TypeScript and JavaScript files via isolated `node` + TypeScript Compiler API
// when `typescript` is resolvable, falling back to structural declaration scanning otherwise.
type TSAnalyzer struct {
	nodeBin      string
	hasTSCModule bool
}

// NewTSAnalyzer probes node and TypeScript module availability without executing target repo code.
func NewTSAnalyzer() *TSAnalyzer {
	bin, _ := exec.LookPath("node")
	hasTSC := false
	if bin != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := exec.CommandContext(ctx, bin, "-e", `require.resolve("typescript")`).Run(); err == nil {
			hasTSC = true
		}
	}
	return &TSAnalyzer{nodeBin: bin, hasTSCModule: hasTSC}
}

func (a *TSAnalyzer) Language() string { return "typescript" }
func (a *TSAnalyzer) Version() string  { return InterfaceVersion }

func (a *TSAnalyzer) Status() AnalyzerStatus {
	if a.nodeBin != "" && a.hasTSCModule {
		return AnalyzerStatus{
			Language:     "typescript",
			Version:      InterfaceVersion,
			Adapter:      "node + typescript.createSourceFile AST",
			Available:    true,
			Capabilities: CapabilityNames(tsCompilerCaps),
			Limitations:  "Single-file TypeScript AST extraction; full cross-file tsc program type-checking requires project node_modules.",
		}
	}
	return AnalyzerStatus{
		Language:     "typescript",
		Version:      InterfaceVersion,
		Adapter:      "structural JS/TS declaration scanner",
		Available:    true,
		Capabilities: CapabilityNames(tsStructuralCaps),
		Limitations:  "typescript npm package not globally resolvable; structural export/import/interface/test extraction active without full type inference.",
	}
}

func (a *TSAnalyzer) SupportsFile(relPath string) bool {
	l := DetectLanguage(relPath)
	return l == "typescript" || l == "javascript"
}

func (a *TSAnalyzer) AnalyzeFiles(ctx context.Context, rootDir string, relPaths []string) ([]FileAnalysis, error) {
	out := make([]FileAnalysis, 0, len(relPaths))
	for _, rel := range relPaths {
		raw, err := workspace.ReadSafeFile(rootDir, rel, 1<<20)
		if err != nil {
			out = append(out, FileAnalysis{Language: DetectLanguage(rel), File: rel, ParseError: err.Error()})
			continue
		}
		if a.nodeBin != "" && a.hasTSCModule {
			if fa, ok := a.analyzeWithTSC(ctx, rel, raw); ok {
				out = append(out, fa)
				continue
			}
		}
		out = append(out, analyzeTSFallback(rel, string(raw)))
	}
	return out, nil
}

func (a *TSAnalyzer) analyzeWithTSC(ctx context.Context, rel string, raw []byte) (FileAnalysis, bool) {
	runCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(runCtx, a.nodeBin, "-e", tsASTHelper, filepath.Base(rel))
	cmd.Stdin = bytes.NewReader(raw)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	if err := cmd.Run(); err != nil {
		return FileAnalysis{}, false
	}
	var parsed struct {
		Imports   []string   `json:"imports"`
		Symbols   []Symbol   `json:"symbols"`
		Contracts []Contract `json:"contracts"`
		Tests     []string   `json:"tests"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &parsed); err != nil {
		return FileAnalysis{}, false
	}
	langName := DetectLanguage(rel)
	for i := range parsed.Symbols {
		parsed.Symbols[i].File = rel
	}
	for i := range parsed.Contracts {
		parsed.Contracts[i].File = rel
	}
	return FileAnalysis{
		Language:     langName,
		File:         rel,
		Capabilities: tsCompilerCaps,
		Imports:      parsed.Imports,
		Symbols:      parsed.Symbols,
		Contracts:    parsed.Contracts,
		Tests:        parsed.Tests,
	}, true
}

var (
	tsImportRe = regexp.MustCompile(`import\s+.*?\s+from\s+["']([^"']+)["']`)
	tsFuncRe   = regexp.MustCompile(`^(export\s+)?(?:async\s+)?function\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\(([^)]*)\)(?:\s*:\s*([^{]+))?`)
	tsIfaceRe  = regexp.MustCompile(`^(export\s+)?(?:interface|type)\s+([A-Za-z_$][A-Za-z0-9_$]*)`)
	tsClassRe  = regexp.MustCompile(`^(export\s+)?class\s+([A-Za-z_$][A-Za-z0-9_$]*)`)
	tsTestRe   = regexp.MustCompile(`(?:test|it)\s*\(\s*["']([^"']+)["']`)
)

func analyzeTSFallback(rel, src string) FileAnalysis {
	fa := FileAnalysis{Language: DetectLanguage(rel), File: rel, Capabilities: tsStructuralCaps}
	for idx, line := range strings.Split(src, "\n") {
		lineNo := idx + 1
		trimmed := strings.TrimSpace(line)
		if m := tsImportRe.FindStringSubmatch(trimmed); m != nil {
			fa.Imports = append(fa.Imports, m[1])
		} else if m := tsFuncRe.FindStringSubmatch(trimmed); m != nil {
			exp := m[1] != ""
			sig := strings.TrimSpace(strings.TrimSuffix(strings.Split(trimmed, "{")[0], "{"))
			fa.Symbols = append(fa.Symbols, Symbol{
				ID: m[2], Name: m[2], Kind: "func", File: rel, StartLine: lineNo, EndLine: lineNo, Exported: exp, Signature: sig,
			})
			if exp {
				fa.Contracts = append(fa.Contracts, Contract{Kind: "function", Name: m[2], File: rel, Line: lineNo, Signature: sig})
			}
		} else if m := tsIfaceRe.FindStringSubmatch(trimmed); m != nil {
			exp := m[1] != ""
			fa.Symbols = append(fa.Symbols, Symbol{
				ID: m[2], Name: m[2], Kind: "interface", File: rel, StartLine: lineNo, EndLine: lineNo, Exported: exp, Signature: trimmed,
			})
			if exp {
				fa.Contracts = append(fa.Contracts, Contract{Kind: "type", Name: m[2], File: rel, Line: lineNo, Signature: trimmed})
			}
		} else if m := tsClassRe.FindStringSubmatch(trimmed); m != nil {
			fa.Symbols = append(fa.Symbols, Symbol{
				ID: m[2], Name: m[2], Kind: "class", File: rel, StartLine: lineNo, EndLine: lineNo, Exported: m[1] != "", Signature: "class " + m[2],
			})
		}
		if m := tsTestRe.FindStringSubmatch(trimmed); m != nil {
			fa.Tests = append(fa.Tests, m[1])
		}
	}
	return fa
}
