package lang

import (
	"context"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/Eresus-Security-OSS/CodeSpider/internal/workspace"
)

const rustCaps = CapSymbols | CapImports | CapContracts | CapTests | CapSemanticDiff

// RustAnalyzer performs structural extraction for Rust source files (`pub fn`, `struct`, `enum`, `trait`, `use`, `#[test]`).
type RustAnalyzer struct{}

// NewRustAnalyzer creates a RustAnalyzer.
func NewRustAnalyzer() *RustAnalyzer { return &RustAnalyzer{} }

func (a *RustAnalyzer) Language() string { return "rust" }
func (a *RustAnalyzer) Version() string  { return InterfaceVersion }

func (a *RustAnalyzer) Status() AnalyzerStatus {
	return AnalyzerStatus{
		Language:     "rust",
		Version:      InterfaceVersion,
		Adapter:      "structural Rust item & contract extractor",
		Available:    true,
		Capabilities: CapabilityNames(rustCaps),
		Limitations:  "Does not expand procedural/declarative macros or run rust-analyzer trait/borrow-checker inference.",
	}
}

func (a *RustAnalyzer) SupportsFile(relPath string) bool {
	return strings.EqualFold(filepath.Ext(relPath), ".rs")
}

var (
	rsUseRe  = regexp.MustCompile(`^(?:pub\s+)?use\s+([^;]+);`)
	rsFnRe   = regexp.MustCompile(`^(pub(?:\([^)]+\))?\s+)?(?:async\s+)?(?:unsafe\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?:<[^>]+>)?\s*\(([^)]*)\)(?:\s*->\s*([^{]+))?`)
	rsTypeRe = regexp.MustCompile(`^(pub(?:\([^)]+\))?\s+)?(struct|enum|trait)\s+([A-Za-z_][A-Za-z0-9_]*)`)
)

func (a *RustAnalyzer) AnalyzeFiles(_ context.Context, rootDir string, relPaths []string) ([]FileAnalysis, error) {
	out := make([]FileAnalysis, 0, len(relPaths))
	for _, rel := range relPaths {
		raw, err := workspace.ReadSafeFile(rootDir, rel, 1<<20)
		if err != nil {
			out = append(out, FileAnalysis{Language: "rust", File: rel, ParseError: err.Error()})
			continue
		}
		fa := FileAnalysis{Language: "rust", File: rel, Capabilities: rustCaps}
		nextIsTest := false
		for idx, line := range strings.Split(string(raw), "\n") {
			lineNo := idx + 1
			trimmed := strings.TrimSpace(line)
			if strings.Contains(trimmed, "#[test]") || strings.Contains(trimmed, "::test]") {
				nextIsTest = true
				continue
			}
			if m := rsUseRe.FindStringSubmatch(trimmed); m != nil {
				fa.Imports = append(fa.Imports, strings.TrimSpace(m[1]))
			} else if m := rsFnRe.FindStringSubmatch(trimmed); m != nil {
				exp := strings.HasPrefix(strings.TrimSpace(m[1]), "pub")
				sig := strings.TrimSpace(strings.Split(trimmed, "{")[0])
				fa.Symbols = append(fa.Symbols, Symbol{
					ID: m[2], Name: m[2], Kind: "func", File: rel, StartLine: lineNo, EndLine: lineNo,
					Exported: exp, Signature: sig, IsTest: nextIsTest,
				})
				if nextIsTest {
					fa.Tests = append(fa.Tests, m[2])
				} else if exp {
					fa.Contracts = append(fa.Contracts, Contract{Kind: "function", Name: m[2], File: rel, Line: lineNo, Signature: sig})
				}
				nextIsTest = false
			} else if m := rsTypeRe.FindStringSubmatch(trimmed); m != nil {
				exp := strings.HasPrefix(strings.TrimSpace(m[1]), "pub")
				fa.Symbols = append(fa.Symbols, Symbol{
					ID: m[3], Name: m[3], Kind: m[2], File: rel, StartLine: lineNo, EndLine: lineNo,
					Exported: exp, Signature: m[2] + " " + m[3],
				})
				if exp {
					fa.Contracts = append(fa.Contracts, Contract{Kind: m[2], Name: m[3], File: rel, Line: lineNo, Signature: m[2] + " " + m[3]})
				}
				nextIsTest = false
			} else if !strings.HasPrefix(trimmed, "#[") {
				nextIsTest = false
			}
		}
		out = append(out, fa)
	}
	return out, nil
}
