// Package analysis implements deterministic, compiler-assisted PR analyzers
// that produce statically supported evidence findings and compact LLM briefs.
package analysis

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Eresus-Security-OSS/CodeSpider/internal/codeintel"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/evidence"
)

// AnalyzeContracts diffs base vs. head Go symbol snapshots to detect breaking API,
// JSON wire-tag, context-propagation, and error-contract changes.
func AnalyzeContracts(base, head *codeintel.Snapshot, commitSHA string) []evidence.Finding {
	if base == nil || head == nil {
		return nil
	}
	var findings []evidence.Finding

	ids := make([]string, 0, len(base.Symbols))
	for id := range base.Symbols {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	for _, id := range ids {
		bSym := base.Symbols[id]
		if !bSym.Exported {
			continue
		}
		hSym, exists := head.Symbols[id]
		if !exists {
			// Only flag removal if the file still exists in head (avoids noise when whole package deleted intentionally unless callers remain).
			callers := head.ReverseCallers[id]
			if len(callers) > 0 {
				f := evidence.Finding{
					RuleID:    "CS-API-001",
					Category:  "api-compatibility",
					Severity:  "critical",
					State:     evidence.StateStaticallySupported,
					Path:      bSym.File,
					StartLine: int64(bSym.StartLine),
					EndLine:   int64(bSym.StartLine),
					Symbol:    id,
					CommitSHA: commitSHA,
					Title:     "Exported symbol removed while callers remain",
					Body:      fmt.Sprintf("Exported %s `%s` was removed, but %d caller(s) still reference it (%s).", bSym.Kind, bSym.Name, len(callers), strings.Join(limitSlice(callers, 4), ", ")),
					Evidence:  []string{"AST diff base vs. head", "call graph reverse callers: " + strings.Join(limitSlice(callers, 4), ", ")},
				}
				f.Fingerprint = evidence.ComputeFingerprint(f.RuleID, f.Category, f.Path, f.Symbol)
				findings = append(findings, f)
			}
			continue
		}

		if (bSym.Kind == "func" || bSym.Kind == "method") && bSym.Signature != hSym.Signature {
			sev := "warning"
			if len(head.ReverseCallers[id]) > 0 || (bSym.TakesContext && !hSym.TakesContext) || (bSym.ReturnsError && !hSym.ReturnsError) {
				sev = "critical"
			}
			var notes []string
			if bSym.TakesContext && !hSym.TakesContext {
				notes = append(notes, "dropped context.Context parameter")
			}
			if bSym.ReturnsError && !hSym.ReturnsError {
				notes = append(notes, "dropped error return")
			}
			detail := fmt.Sprintf("Signature changed from `%s` to `%s`.", bSym.Signature, hSym.Signature)
			if len(notes) > 0 {
				detail += " (" + strings.Join(notes, ", ") + ")"
			}
			f := evidence.Finding{
				RuleID:    "CS-API-002",
				Category:  "behavioral-contract",
				Severity:  sev,
				State:     evidence.StateStaticallySupported,
				Path:      hSym.File,
				StartLine: int64(hSym.StartLine),
				EndLine:   int64(hSym.EndLine),
				Symbol:    id,
				CommitSHA: commitSHA,
				Title:     "Breaking exported signature / contract change",
				Body:      detail,
				Evidence:  []string{"base signature: " + bSym.Signature, "head signature: " + hSym.Signature},
			}
			f.Fingerprint = evidence.ComputeFingerprint(f.RuleID, f.Category, f.Path, f.Symbol)
			findings = append(findings, f)
		}

		if len(bSym.JSONTags) > 0 {
			for field, oldTag := range bSym.JSONTags {
				newTag, ok := hSym.JSONTags[field]
				if !ok || newTag != oldTag {
					f := evidence.Finding{
						RuleID:    "CS-API-003",
						Category:  "api-compatibility",
						Severity:  "warning",
						State:     evidence.StateStaticallySupported,
						Path:      hSym.File,
						StartLine: int64(hSym.StartLine),
						EndLine:   int64(hSym.EndLine),
						Symbol:    id + "." + field,
						CommitSHA: commitSHA,
						Title:     "JSON wire tag modified",
						Body:      fmt.Sprintf("Struct `%s` field `%s` changed JSON tag from %q to %q, which may break API clients or persisted state.", bSym.Name, field, oldTag, newTag),
						Evidence:  []string{fmt.Sprintf("json tag %s: %q -> %q", field, oldTag, newTag)},
					}
					f.Fingerprint = evidence.ComputeFingerprint(f.RuleID, f.Category, f.Path, f.Symbol)
					findings = append(findings, f)
				}
			}
		}

		if bSym.Kind == "interface" && strings.Join(bSym.InterfaceMethods, ";") != strings.Join(hSym.InterfaceMethods, ";") {
			f := evidence.Finding{
				RuleID:    "CS-API-004",
				Category:  "api-compatibility",
				Severity:  "critical",
				State:     evidence.StateStaticallySupported,
				Path:      hSym.File,
				StartLine: int64(hSym.StartLine),
				EndLine:   int64(hSym.EndLine),
				Symbol:    id,
				CommitSHA: commitSHA,
				Title:     "Exported interface method set changed",
				Body:      fmt.Sprintf("Exported interface `%s` changed methods from %v to %v, which breaks downstream implementers.", bSym.Name, bSym.InterfaceMethods, hSym.InterfaceMethods),
				Evidence:  []string{"base interface methods: " + strings.Join(bSym.InterfaceMethods, ", "), "head interface methods: " + strings.Join(hSym.InterfaceMethods, ", ")},
			}
			f.Fingerprint = evidence.ComputeFingerprint(f.RuleID, f.Category, f.Path, f.Symbol)
			findings = append(findings, f)
		}
	}
	return findings
}

func limitSlice(s []string, max int) []string {
	if len(s) <= max {
		return s
	}
	return s[:max]
}
