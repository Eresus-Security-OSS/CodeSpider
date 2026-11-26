package lang

import (
	"context"
	"path/filepath"
	"strings"

	"github.com/Eresus-Security-OSS/CodeSpider/internal/codeintel"
)

const goCaps = CapSyntax | CapSymbols | CapImports | CapTypes | CapCalls | CapCFG | CapDataFlow | CapSemanticDiff | CapContracts | CapTests

// GoAnalyzer implements deep Go code intelligence using go/ast, go/types, and codeintel.
type GoAnalyzer struct {
	indexer *codeintel.Indexer
}

// NewGoAnalyzer returns a GoAnalyzer backed by a content-addressed codeintel.Indexer.
func NewGoAnalyzer() *GoAnalyzer {
	return &GoAnalyzer{indexer: codeintel.NewIndexer()}
}

func (a *GoAnalyzer) Language() string { return "go" }
func (a *GoAnalyzer) Version() string  { return InterfaceVersion }

func (a *GoAnalyzer) Status() AnalyzerStatus {
	return AnalyzerStatus{
		Language:     "go",
		Version:      InterfaceVersion,
		Adapter:      "stdlib go/ast + go/types + CFG",
		Available:    true,
		Capabilities: CapabilityNames(goCaps),
		Limitations:  "External third-party modules without cached .a archives are tracked as unresolved imports rather than full type-checked targets.",
	}
}

func (a *GoAnalyzer) SupportsFile(relPath string) bool {
	return strings.HasSuffix(strings.ToLower(relPath), ".go")
}

func (a *GoAnalyzer) AnalyzeFiles(_ context.Context, rootDir string, relPaths []string) ([]FileAnalysis, error) {
	snap, err := a.indexer.IndexWorktree(rootDir, "")
	if err != nil {
		return nil, err
	}
	want := make(map[string]bool, len(relPaths))
	for _, p := range relPaths {
		want[filepath.ToSlash(p)] = true
	}

	byFile := make(map[string]*FileAnalysis)
	for _, p := range relPaths {
		slash := filepath.ToSlash(p)
		byFile[slash] = &FileAnalysis{
			Language:     "go",
			File:         slash,
			Capabilities: goCaps,
		}
	}

	for _, ps := range snap.Packages {
		for _, sym := range ps.Symbols {
			fa, ok := byFile[sym.File]
			if !ok && len(want) > 0 {
				continue
			}
			if fa == nil {
				fa = &FileAnalysis{Language: "go", File: sym.File, Capabilities: goCaps}
				byFile[sym.File] = fa
			}
			fa.Imports = ps.Imports
			isTest := strings.HasSuffix(sym.File, "_test.go") && strings.HasPrefix(sym.Name, "Test")
			fa.Symbols = append(fa.Symbols, Symbol{
				ID:        sym.ID,
				Name:      sym.Name,
				Kind:      sym.Kind,
				File:      sym.File,
				StartLine: sym.StartLine,
				EndLine:   sym.EndLine,
				Exported:  sym.Exported,
				Signature: sym.Signature,
				Calls:     sym.Calls,
				IsTest:    isTest,
			})
			if isTest {
				fa.Tests = append(fa.Tests, sym.Name)
			}
			if sym.Exported {
				fa.Contracts = append(fa.Contracts, Contract{
					Kind:      sym.Kind,
					Name:      sym.ID,
					File:      sym.File,
					Line:      sym.StartLine,
					Signature: sym.Signature,
				})
			}
		}
	}

	out := make([]FileAnalysis, 0, len(byFile))
	for _, p := range relPaths {
		if fa, ok := byFile[filepath.ToSlash(p)]; ok {
			out = append(out, *fa)
		}
	}
	return out, nil
}
