// Package lang defines versioned polyglot code-intelligence analyzer interfaces,
// explicit capability negotiation, and isolated adapters for Go, Python, TypeScript/JavaScript, and Rust.
package lang

import (
	"context"
	"path/filepath"
	"strings"
)

// InterfaceVersion is the version of the CodeSpider polyglot analyzer contract.
const InterfaceVersion = "v1"

// Capability is a bitmask of analysis features an analyzer genuinely provides.
type Capability uint32

const (
	CapSyntax Capability = 1 << iota
	CapSymbols
	CapImports
	CapTypes
	CapCalls
	CapCFG
	CapDataFlow
	CapSemanticDiff
	CapContracts
	CapTests
)

// Has reports whether all capability bits in req are supported.
func (c Capability) Has(req Capability) bool {
	return c&req == req
}

// CapabilityNames returns human-readable names of enabled capability bits.
func CapabilityNames(c Capability) []string {
	ordered := []struct {
		bit  Capability
		name string
	}{
		{CapSyntax, "syntax"},
		{CapSymbols, "symbols"},
		{CapImports, "imports"},
		{CapTypes, "types"},
		{CapCalls, "calls"},
		{CapCFG, "cfg"},
		{CapDataFlow, "data_flow"},
		{CapSemanticDiff, "semantic_diff"},
		{CapContracts, "contracts"},
		{CapTests, "tests"},
	}
	var out []string
	for _, item := range ordered {
		if c.Has(item.bit) {
			out = append(out, item.name)
		}
	}
	return out
}

// Symbol is a language-neutral code declaration extracted by a language analyzer.
type Symbol struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Kind       string   `json:"kind"` // func, method, class, struct, interface, trait, enum, route, test
	File       string   `json:"file"`
	StartLine  int      `json:"start_line"`
	EndLine    int      `json:"end_line"`
	Exported   bool     `json:"exported"`
	Signature  string   `json:"signature"`
	Calls      []string `json:"calls,omitempty"`
	Decorators []string `json:"decorators,omitempty"`
	IsTest     bool     `json:"is_test,omitempty"`
}

// Contract represents an exported API, HTTP route, schema, or public symbol contract.
type Contract struct {
	Kind      string `json:"kind"` // function, interface, http_route, schema
	Name      string `json:"name"`
	File      string `json:"file"`
	Line      int    `json:"line"`
	Signature string `json:"signature"`
}

// FileAnalysis holds extracted intelligence for a single source file.
type FileAnalysis struct {
	Language     string     `json:"language"`
	File         string     `json:"file"`
	Capabilities Capability `json:"capabilities"`
	ParseError   string     `json:"parse_error,omitempty"`
	Imports      []string   `json:"imports,omitempty"`
	Symbols      []Symbol   `json:"symbols,omitempty"`
	Contracts    []Contract `json:"contracts,omitempty"`
	Tests        []string   `json:"tests,omitempty"`
}

// AnalyzerStatus reports honest runtime availability and exact capabilities.
type AnalyzerStatus struct {
	Language     string   `json:"language"`
	Version      string   `json:"version"`
	Adapter      string   `json:"adapter"`
	Available    bool     `json:"available"`
	Capabilities []string `json:"capabilities"`
	Limitations  string   `json:"limitations"`
}

// Analyzer is the versioned interface implemented by each language backend.
type Analyzer interface {
	Language() string
	Version() string
	Status() AnalyzerStatus
	SupportsFile(relPath string) bool
	AnalyzeFiles(ctx context.Context, rootDir string, relPaths []string) ([]FileAnalysis, error)
}

// Registry dispatches file lists to matching language analyzers.
type Registry struct {
	analyzers []Analyzer
}

// NewDefaultRegistry constructs a Registry with Go, Python, TypeScript/JavaScript, and Rust analyzers.
func NewDefaultRegistry() *Registry {
	return &Registry{
		analyzers: []Analyzer{
			NewGoAnalyzer(),
			NewPythonAnalyzer(),
			NewTSAnalyzer(),
			NewRustAnalyzer(),
		},
	}
}

// Statuses returns capability and availability status for all registered analyzers.
func (r *Registry) Statuses() []AnalyzerStatus {
	out := make([]AnalyzerStatus, 0, len(r.analyzers))
	for _, a := range r.analyzers {
		out = append(out, a.Status())
	}
	return out
}

// AnalyzerForFile returns the matching Analyzer for relPath, or nil if unsupported.
func (r *Registry) AnalyzerForFile(relPath string) Analyzer {
	for _, a := range r.analyzers {
		if a.SupportsFile(relPath) {
			return a
		}
	}
	return nil
}

// AnalyzeFiles groups relPaths by language analyzer and returns all FileAnalysis results.
func (r *Registry) AnalyzeFiles(ctx context.Context, rootDir string, relPaths []string) ([]FileAnalysis, error) {
	grouped := make(map[string][]string)
	byLang := make(map[string]Analyzer)
	for _, p := range relPaths {
		a := r.AnalyzerForFile(p)
		if a == nil {
			continue
		}
		langName := a.Language()
		byLang[langName] = a
		grouped[langName] = append(grouped[langName], filepath.ToSlash(p))
	}
	var all []FileAnalysis
	for langName, files := range grouped {
		res, err := byLang[langName].AnalyzeFiles(ctx, rootDir, files)
		if err != nil {
			return all, err
		}
		all = append(all, res...)
	}
	return all, nil
}

// DetectLanguage maps a file path extension to a canonical language name.
func DetectLanguage(relPath string) string {
	ext := strings.ToLower(filepath.Ext(relPath))
	switch ext {
	case ".go":
		return "go"
	case ".py":
		return "python"
	case ".ts", ".tsx", ".mts", ".cts":
		return "typescript"
	case ".js", ".jsx", ".mjs", ".cjs":
		return "javascript"
	case ".rs":
		return "rust"
	case ".sql":
		return "sql"
	default:
		return ""
	}
}
