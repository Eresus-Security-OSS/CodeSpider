package analysis

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/Eresus-Security-OSS/CodeSpider/internal/codeintel"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/evidence"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/semdiff"
)

// Input bundles repository snapshots and diff inputs for deterministic analysis.
type Input struct {
	RepoSlug      string
	PRNumber      int64
	BaseSHA       string
	HeadSHA       string
	BaseWorktree  string
	HeadWorktree  string
	Diff          string
	ChangedPaths  []string
	ForbidImports map[string][]string
	DryRun        bool
}

// Report contains all deterministic findings, semantic diff summary, impacted tests, cross-PR conflicts, and a compact LLM brief.
type Report struct {
	CacheKey      string              `json:"cache_key"`
	Findings      []evidence.Finding  `json:"findings"`
	SemanticDiff  semdiff.DiffSummary `json:"semantic_diff"`
	ImpactedTests []string            `json:"impacted_tests,omitempty"`
	Conflicts     []string            `json:"conflicts,omitempty"`
	Brief         string              `json:"brief"`
	CacheHit      bool                `json:"cache_hit"`
}

// Pipeline runs deterministic code intelligence and static analyzers with content-addressed caching.
type Pipeline struct {
	indexer   *codeintel.Indexer
	conflicts *ConflictTracker
	mu        sync.Mutex
	cache     map[string]Report
}

// NewPipeline creates a deterministic analysis Pipeline.
func NewPipeline() *Pipeline {
	return &Pipeline{
		indexer:   codeintel.NewIndexer(),
		conflicts: NewConflictTracker(),
		cache:     make(map[string]Report),
	}
}

// Run executes deterministic analyzers (or returns a cached Report for identical commit/policy inputs).
func (p *Pipeline) Run(in Input) Report {
	cacheKey := computeReportKey(in)
	p.mu.Lock()
	if cached, ok := p.cache[cacheKey]; ok {
		p.mu.Unlock()
		cached.CacheHit = true
		return cached
	}
	p.mu.Unlock()

	var baseSnap, headSnap *codeintel.Snapshot
	if in.BaseWorktree != "" {
		baseSnap, _ = p.indexer.IndexWorktree(in.BaseWorktree, in.BaseSHA)
	}
	if in.HeadWorktree != "" {
		headSnap, _ = p.indexer.IndexWorktree(in.HeadWorktree, in.HeadSHA)
	}

	var findings []evidence.Finding
	findings = append(findings, AnalyzeContracts(baseSnap, headSnap, in.HeadSHA)...)
	findings = append(findings, AnalyzeArchitecture(headSnap, in.ForbidImports, in.HeadSHA)...)
	findings = append(findings, AnalyzeSecurityInvariantsAST(in.BaseWorktree, in.HeadWorktree, in.Diff, in.HeadSHA)...)
	findings = append(findings, AnalyzeGoCFGAndDataFlow(in.HeadWorktree, in.ChangedPaths, in.HeadSHA)...)
	findings = append(findings, AnalyzeMigrations(in.Diff, in.ChangedPaths, in.HeadSHA)...)
	findings = append(findings, AnalyzeDepsAndIaC(in.Diff, in.HeadSHA)...)

	semSummary := semdiff.Analyze(semdiff.Input{
		BaseWorktree: in.BaseWorktree,
		HeadWorktree: in.HeadWorktree,
		BaseSnap:     baseSnap,
		HeadSnap:     headSnap,
		Diff:         in.Diff,
		ChangedPaths: in.ChangedPaths,
	})

	impactedTests, testFindings := AnalyzeTestImpact(headSnap, in.ChangedPaths, semSummary, in.HeadSHA)
	// Without a base snapshot we cannot prove an exported symbol actually changed behavior,
	// so CS-TEST-001 is only emitted when a base comparison exists (avoids noise on new/unknown files).
	if baseSnap != nil {
		findings = append(findings, testFindings...)
	}

	var touchedSyms []string
	if headSnap != nil {
		changedSet := make(map[string]bool, len(in.ChangedPaths))
		for _, cp := range in.ChangedPaths {
			changedSet[cp] = true
		}
		for id, sym := range headSnap.Symbols {
			if changedSet[sym.File] {
				touchedSyms = append(touchedSyms, id)
			}
		}
	}
	var conflicts []string
	if in.DryRun {
		conflicts = p.conflicts.DetectOnly(in.RepoSlug, in.PRNumber, in.HeadSHA, in.ChangedPaths, touchedSyms)
	} else {
		conflicts = p.conflicts.UpdateAndDetect(in.RepoSlug, in.PRNumber, in.HeadSHA, in.ChangedPaths, touchedSyms)
	}

	rep := Report{
		CacheKey:      cacheKey,
		Findings:      findings,
		SemanticDiff:  semSummary,
		ImpactedTests: impactedTests,
		Conflicts:     conflicts,
	}
	rep.Brief = formatCompactBrief(rep)

	p.mu.Lock()
	if len(p.cache) > 256 {
		p.cache = make(map[string]Report)
	}
	p.cache[cacheKey] = rep
	p.mu.Unlock()

	return rep
}

func formatCompactBrief(rep Report) string {
	if len(rep.Findings) == 0 && len(rep.ImpactedTests) == 0 && len(rep.Conflicts) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("## Deterministic Analysis Brief\n")
	if len(rep.Findings) > 0 {
		b.WriteString("Static analyzers flagged:\n")
		for i, f := range rep.Findings {
			if i >= 12 {
				fmt.Fprintf(&b, "- ... (%d more static findings)\n", len(rep.Findings)-12)
				break
			}
			fmt.Fprintf(&b, "- [%s] %s (%s:%d): %s\n", strings.ToUpper(f.Severity), f.RuleID, f.Path, f.EndLine, f.Title)
		}
	}
	if len(rep.ImpactedTests) > 0 {
		fmt.Fprintf(&b, "Impacted Go tests: %s\n", strings.Join(limitSlice(rep.ImpactedTests, 8), ", "))
	}
	if len(rep.Conflicts) > 0 {
		fmt.Fprintf(&b, "Cross-PR semantic overlaps: %s\n", strings.Join(limitSlice(rep.Conflicts, 4), "; "))
	}
	return b.String()
}

func computeReportKey(in Input) string {
	h := sha256.New()
	h.Write([]byte(in.RepoSlug + "\x00" + in.BaseSHA + "\x00" + in.HeadSHA + "\x00"))
	diffSum := sha256.Sum256([]byte(in.Diff))
	h.Write(diffSum[:])
	keys := make([]string, 0, len(in.ForbidImports))
	for k := range in.ForbidImports {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		h.Write([]byte(k + ":" + strings.Join(in.ForbidImports[k], ",") + ";"))
	}
	return hex.EncodeToString(h.Sum(nil)[:8])
}
