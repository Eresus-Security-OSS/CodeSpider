package analysis

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/Eresus-Security-OSS/CodeSpider/internal/codeintel"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/evidence"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/semdiff"
)

// PRFootprint records files and symbol IDs touched by an open PR for cross-PR conflict detection.
type PRFootprint struct {
	PRNumber int64
	HeadSHA  string
	Files    map[string]bool
	Symbols  map[string]bool
}

// ConflictTracker detects file and semantic symbol overlaps across concurrent open PRs in a repository.
type ConflictTracker struct {
	mu    sync.RWMutex
	byPRs map[string]map[int64]PRFootprint // repoSlug -> prNumber -> footprint
}

// NewConflictTracker creates a thread-safe ConflictTracker.
func NewConflictTracker() *ConflictTracker {
	return &ConflictTracker{
		byPRs: make(map[string]map[int64]PRFootprint),
	}
}

// UpdateAndDetect registers the current PR footprint and returns warnings for overlapping open PRs.
func (ct *ConflictTracker) UpdateAndDetect(repoSlug string, prNumber int64, headSHA string, files []string, symbols []string) []string {
	return ct.detect(repoSlug, prNumber, headSHA, files, symbols, true)
}

// DetectOnly checks for overlapping open PRs without mutating ConflictTracker state (used by dry-run).
func (ct *ConflictTracker) DetectOnly(repoSlug string, prNumber int64, headSHA string, files []string, symbols []string) []string {
	return ct.detect(repoSlug, prNumber, headSHA, files, symbols, false)
}

func (ct *ConflictTracker) detect(repoSlug string, prNumber int64, headSHA string, files []string, symbols []string, mutate bool) []string {
	if ct == nil || repoSlug == "" || prNumber <= 0 {
		return nil
	}
	fileSet := make(map[string]bool, len(files))
	for _, f := range files {
		fileSet[f] = true
	}
	symSet := make(map[string]bool, len(symbols))
	for _, s := range symbols {
		symSet[s] = true
	}

	ct.mu.Lock()
	defer ct.mu.Unlock()
	if ct.byPRs[repoSlug] == nil {
		if !mutate {
			return nil
		}
		ct.byPRs[repoSlug] = make(map[int64]PRFootprint)
	}

	var conflicts []string
	for otherPR, fp := range ct.byPRs[repoSlug] {
		if otherPR == prNumber {
			continue
		}
		var sharedFiles, sharedSyms []string
		for f := range fileSet {
			if fp.Files[f] {
				sharedFiles = append(sharedFiles, f)
			}
		}
		for s := range symSet {
			if fp.Symbols[s] {
				sharedSyms = append(sharedSyms, s)
			}
		}
		if len(sharedFiles) > 0 || len(sharedSyms) > 0 {
			sort.Strings(sharedFiles)
			sort.Strings(sharedSyms)
			conflicts = append(conflicts, fmt.Sprintf("PR #%d overlaps on %d file(s) %v / %d symbol(s) %v",
				otherPR, len(sharedFiles), limitSlice(sharedFiles, 3), len(sharedSyms), limitSlice(sharedSyms, 3)))
		}
	}

	if mutate {
		ct.byPRs[repoSlug][prNumber] = PRFootprint{
			PRNumber: prNumber,
			HeadSHA:  headSHA,
			Files:    fileSet,
			Symbols:  symSet,
		}
	}
	sort.Strings(conflicts)
	return conflicts
}

// AnalyzeTestImpact identifies impacted Go tests via ReverseCallers and flags untested exported changes,
// skipping comment-only or behaviorally equivalent refactorings.
func AnalyzeTestImpact(head *codeintel.Snapshot, changedPaths []string, sem semdiff.DiffSummary, commitSHA string) (impactedTests []string, findings []evidence.Finding) {
	if head == nil || len(changedPaths) == 0 {
		return nil, nil
	}
	changedSet := make(map[string]bool, len(changedPaths))
	hasTestChanges := false
	for _, p := range changedPaths {
		slash := filepath.ToSlash(p)
		changedSet[slash] = true
		if strings.HasSuffix(slash, "_test.go") {
			hasTestChanges = true
		}
	}

	var changedExported []codeintel.Symbol
	var changedIDs []string
	for id, sym := range head.Symbols {
		if changedSet[sym.File] {
			changedIDs = append(changedIDs, id)
			if sym.Exported && (sym.Kind == "func" || sym.Kind == "method") && !strings.HasSuffix(sym.File, "_test.go") {
				changedExported = append(changedExported, sym)
			}
		}
	}
	sort.Strings(changedIDs)
	impactedTests = head.ImpactedTests(changedIDs, 3)

	if sem.OnlyEquivalentOrDocs {
		return impactedTests, nil
	}
	hasBehavioralChange := len(sem.Changes) == 0
	for _, c := range sem.Changes {
		if !c.BehaviorallyEquivalent && c.Kind != semdiff.ChangeTestChanged && c.Kind != semdiff.ChangeConfigOrDocs {
			hasBehavioralChange = true
			break
		}
	}
	if !hasBehavioralChange {
		return impactedTests, nil
	}

	if len(changedExported) > 0 && !hasTestChanges && len(impactedTests) == 0 {
		sym := changedExported[0]
		f := evidence.Finding{
			RuleID:    "CS-TEST-001",
			Category:  "test-impact",
			Severity:  "warning",
			State:     evidence.StateStaticallySupported,
			Path:      sym.File,
			StartLine: int64(sym.StartLine),
			EndLine:   int64(sym.EndLine),
			Symbol:    sym.ID,
			CommitSHA: commitSHA,
			Title:     "Exported Go behavior changed without test coverage",
			Body:      fmt.Sprintf("Modified %d exported Go function(s)/method(s) (e.g. `%s`) with no test file changes and zero statically reachable `Test*` callers.", len(changedExported), sym.Name),
			Evidence:  []string{"call-graph reverse caller traversal (3 hops) found 0 Test* functions"},
		}
		f.Fingerprint = evidence.ComputeFingerprint(f.RuleID, f.Category, f.Path, f.Symbol)
		findings = append(findings, f)
	}
	return impactedTests, findings
}
