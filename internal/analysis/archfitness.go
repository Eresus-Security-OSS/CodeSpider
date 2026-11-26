package analysis

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Eresus-Security-OSS/CodeSpider/internal/codeintel"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/evidence"
)

// AnalyzeArchitecture checks import cycles and repository-defined forbid_imports fitness rules.
func AnalyzeArchitecture(head *codeintel.Snapshot, forbidImports map[string][]string, commitSHA string) []evidence.Finding {
	if head == nil {
		return nil
	}
	var findings []evidence.Finding

	for _, cyc := range head.FindImportCycles() {
		f := evidence.Finding{
			RuleID:    "CS-ARCH-001",
			Category:  "architecture",
			Severity:  "critical",
			State:     evidence.StateStaticallySupported,
			Path:      cyc[0],
			EndLine:   1,
			Symbol:    strings.Join(cyc, "->"),
			CommitSHA: commitSHA,
			Title:     "Package import cycle detected",
			Body:      fmt.Sprintf("Import cycle detected: `%s`.", strings.Join(cyc, " -> ")),
			Evidence:  []string{"import graph cycle: " + strings.Join(cyc, " -> ")},
		}
		f.Fingerprint = evidence.ComputeFingerprint(f.RuleID, f.Category, f.Path, f.Symbol)
		findings = append(findings, f)
	}

	if len(forbidImports) > 0 {
		pkgs := make([]string, 0, len(head.Packages))
		for p := range head.Packages {
			pkgs = append(pkgs, p)
		}
		sort.Strings(pkgs)
		for _, pkgDir := range pkgs {
			ps := head.Packages[pkgDir]
			for pattern, forbidden := range forbidImports {
				if !matchPkgPattern(pkgDir, pattern) {
					continue
				}
				for _, imp := range ps.Imports {
					for _, bad := range forbidden {
						if imp == bad || strings.HasSuffix(imp, "/"+bad) || strings.Contains(imp, bad) {
							targetFile := pkgDir
							if len(ps.Files) > 0 {
								targetFile = ps.Files[0]
							}
							f := evidence.Finding{
								RuleID:    "CS-ARCH-002",
								Category:  "architecture",
								Severity:  "warning",
								State:     evidence.StateStaticallySupported,
								Path:      targetFile,
								EndLine:   1,
								Symbol:    pkgDir + "->" + imp,
								CommitSHA: commitSHA,
								Title:     "Architecture boundary violation",
								Body:      fmt.Sprintf("Package `%s` imports forbidden dependency `%s` (violates rule `%s`).", pkgDir, imp, pattern),
								Evidence:  []string{fmt.Sprintf("import %q matched forbid_imports[%q]", imp, pattern)},
							}
							f.Fingerprint = evidence.ComputeFingerprint(f.RuleID, f.Category, f.Path, f.Symbol)
							findings = append(findings, f)
						}
					}
				}
			}
		}
	}
	return findings
}

func matchPkgPattern(pkgDir, pattern string) bool {
	p := strings.TrimSuffix(filepath.ToSlash(strings.TrimSpace(pattern)), "/**")
	p = strings.TrimSuffix(p, "/*")
	if p == "" || p == "*" {
		return true
	}
	return pkgDir == p || strings.HasPrefix(pkgDir, p+"/")
}
