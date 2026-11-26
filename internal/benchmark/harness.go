// Package benchmark provides a reproducible evaluation harness for ReviewBench,
// SWE-PRBench-style JSONL fixtures, and local regression suites.
package benchmark

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/Eresus-Security-OSS/CodeSpider/internal/analysis"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/evidence"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/repoconfig"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/security"
)

// ExpectedIssue represents a single ground-truth issue in a benchmark PR fixture.
type ExpectedIssue struct {
	File     string `json:"file"`
	Line     int64  `json:"line"`
	Category string `json:"category"`
	Severity string `json:"severity"`
}

// Case models one pull request evaluation fixture (ReviewBench / SWE-PRBench compatible).
type Case struct {
	ID            string            `json:"id"`
	Repo          string            `json:"repo"`
	Language      string            `json:"language"`
	Diff          string            `json:"diff"`
	CommitPatches string            `json:"commit_patches,omitempty"`
	BaseFiles     map[string]string `json:"base_files,omitempty"`
	Files         map[string]string `json:"files,omitempty"`
	Expected      []ExpectedIssue   `json:"expected"`
}

// Summary aggregates precision, recall, F1, confidence intervals, false-positive rate, line accuracy, and resource usage.
type Summary struct {
	Dataset             string                     `json:"dataset"`
	Split               string                     `json:"split,omitempty"`
	Mode                string                     `json:"mode"`
	Cases               int                        `json:"cases"`
	TruePositives       int                        `json:"true_positives"`
	FalsePositives      int                        `json:"false_positives"`
	FalseNegatives      int                        `json:"false_negatives"`
	CleanCases          int                        `json:"clean_cases"`
	CleanCasesFlagged   int                        `json:"clean_cases_flagged"`
	Precision           float64                    `json:"precision"`
	PrecisionCI         ConfidenceInterval         `json:"precision_ci_95"`
	Recall              float64                    `json:"recall"`
	RecallCI            ConfidenceInterval         `json:"recall_ci_95"`
	F1                  float64                    `json:"f1"`
	FalsePositiveRate   float64                    `json:"false_positive_rate"`
	FPRateCI            ConfidenceInterval         `json:"fp_rate_ci_95"`
	FalsePositivesPerPR float64                    `json:"false_positives_per_pr"`
	LineAccuracy        float64                    `json:"line_accuracy"`
	SeverityAccuracy    float64                    `json:"severity_accuracy"`
	ByCategory          map[string]CategorySummary `json:"by_category,omitempty"`
	AvgLatencyMs        float64                    `json:"avg_latency_ms"`
	PeakAllocBytes      uint64                     `json:"peak_alloc_bytes"`
}

// LoadJSONL loads benchmark cases from a JSONL file.
func LoadJSONL(path string) ([]Case, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var cases []Case
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		var c Case
		if err := json.Unmarshal([]byte(line), &c); err != nil {
			return nil, err
		}
		cases = append(cases, c)
	}
	return cases, sc.Err()
}

// RunOffline evaluates CodeSpider's deterministic analysis + secret scanner across cases.
func RunOffline(datasetName string, cases []Case) (Summary, error) {
	return RunWithMode(datasetName, "offline-deterministic", cases, nil)
}

// RunWithMode evaluates deterministic-only, llm-only, or hybrid mode with Wilson 95% confidence intervals.
func RunWithMode(datasetName, mode string, cases []Case, llmPredictor PredictorFunc) (Summary, error) {
	sum := Summary{
		Dataset:    datasetName,
		Split:      strings.TrimSuffix(filepath.Base(datasetName), ".jsonl"),
		Mode:       mode,
		Cases:      len(cases),
		ByCategory: make(map[string]CategorySummary),
	}
	pipe := analysis.NewPipeline()
	var totalLatency time.Duration
	var lineHits, lineChecks int
	var sevHits, sevChecks int
	var memStatsBefore, memStatsAfter runtime.MemStats
	runtime.ReadMemStats(&memStatsBefore)

	for i, c := range cases {
		start := time.Now()
		var predicted []evidence.Finding

		if mode != "llm-only" {
			baseDir, err := materializeFiles(c.BaseFiles)
			if err != nil {
				return sum, err
			}
			headDir, err := materializeFiles(c.Files)
			if err != nil {
				_ = os.RemoveAll(baseDir)
				return sum, err
			}

			changed := repoconfig.ExtractChangedPaths(c.Diff)
			rep := pipe.Run(analysis.Input{
				RepoSlug:     c.Repo,
				PRNumber:     int64(i + 1),
				BaseSHA:      "base-" + c.ID,
				HeadSHA:      "head-" + c.ID,
				BaseWorktree: baseDir,
				HeadWorktree: headDir,
				Diff:         c.Diff,
				ChangedPaths: changed,
				DryRun:       true,
			})
			secFindings := security.ScanPatches(c.CommitPatches, c.Diff)

			_ = os.RemoveAll(baseDir)
			_ = os.RemoveAll(headDir)

			predicted = append(predicted, rep.Findings...)
			for _, sf := range secFindings {
				predicted = append(predicted, evidence.Finding{
					RuleID:   "CS-SECRET-001",
					Category: "security",
					Severity: "critical",
					State:    evidence.StateStaticallySupported,
					Path:     sf.File,
					EndLine:  int64(sf.Line),
					Body:     sf.Kind,
				})
			}
		}

		if (mode == "llm-only" || mode == "hybrid") && llmPredictor != nil {
			predicted = append(predicted, llmPredictor(c)...)
		}

		totalLatency += time.Since(start)

		if len(c.Expected) == 0 {
			sum.CleanCases++
			if len(predicted) > 0 {
				sum.CleanCasesFlagged++
			}
		}

		matchedPred := make([]bool, len(predicted))
		for _, exp := range c.Expected {
			catKey := strings.ToLower(exp.Category)
			cs := sum.ByCategory[catKey]
			found := false
			for pi, pred := range predicted {
				if matchedPred[pi] {
					continue
				}
				if matchFileAndCategory(exp, pred) {
					matchedPred[pi] = true
					found = true
					sum.TruePositives++
					cs.TruePositives++
					if exp.Line > 0 {
						lineChecks++
						if abs64(pred.EndLine-exp.Line) <= 3 {
							lineHits++
						}
					}
					if exp.Severity != "" {
						sevChecks++
						if strings.EqualFold(exp.Severity, pred.Severity) {
							sevHits++
						}
					}
					break
				}
			}
			if !found {
				sum.FalseNegatives++
				cs.FalseNegatives++
			}
			sum.ByCategory[catKey] = cs
		}
		for pi, pred := range predicted {
			if !matchedPred[pi] {
				sum.FalsePositives++
				catKey := strings.ToLower(pred.Category)
				cs := sum.ByCategory[catKey]
				cs.FalsePositives++
				sum.ByCategory[catKey] = cs
			}
		}
	}

	runtime.ReadMemStats(&memStatsAfter)
	if memStatsAfter.TotalAlloc > memStatsBefore.TotalAlloc {
		sum.PeakAllocBytes = memStatsAfter.TotalAlloc - memStatsBefore.TotalAlloc
	}
	if len(cases) > 0 {
		sum.AvgLatencyMs = float64(totalLatency.Milliseconds()) / float64(len(cases))
		sum.FalsePositivesPerPR = float64(sum.FalsePositives) / float64(len(cases))
	}
	if tpFp := sum.TruePositives + sum.FalsePositives; tpFp > 0 {
		sum.Precision = float64(sum.TruePositives) / float64(tpFp)
		sum.PrecisionCI = WilsonInterval(sum.TruePositives, tpFp, 1.96)
	}
	if tpFn := sum.TruePositives + sum.FalseNegatives; tpFn > 0 {
		sum.Recall = float64(sum.TruePositives) / float64(tpFn)
		sum.RecallCI = WilsonInterval(sum.TruePositives, tpFn, 1.96)
	}
	if sum.Precision+sum.Recall > 0 {
		sum.F1 = 2 * sum.Precision * sum.Recall / (sum.Precision + sum.Recall)
	}
	if sum.CleanCases > 0 {
		sum.FalsePositiveRate = float64(sum.CleanCasesFlagged) / float64(sum.CleanCases)
		sum.FPRateCI = WilsonInterval(sum.CleanCasesFlagged, sum.CleanCases, 1.96)
	}
	if lineChecks > 0 {
		sum.LineAccuracy = float64(lineHits) / float64(lineChecks)
	}
	if sevChecks > 0 {
		sum.SeverityAccuracy = float64(sevHits) / float64(sevChecks)
	}
	for k, cs := range sum.ByCategory {
		if cs.TruePositives+cs.FalsePositives > 0 {
			cs.Precision = float64(cs.TruePositives) / float64(cs.TruePositives+cs.FalsePositives)
		}
		if cs.TruePositives+cs.FalseNegatives > 0 {
			cs.Recall = float64(cs.TruePositives) / float64(cs.TruePositives+cs.FalseNegatives)
		}
		sum.ByCategory[k] = cs
	}
	return sum, nil
}

func materializeFiles(files map[string]string) (string, error) {
	if len(files) == 0 {
		return "", nil
	}
	dir, err := os.MkdirTemp("", "codespider-bench-*")
	if err != nil {
		return "", err
	}
	for rel, content := range files {
		clean := filepath.Clean(rel)
		if filepath.IsAbs(clean) || strings.HasPrefix(clean, "..") {
			continue
		}
		dst := filepath.Join(dir, clean)
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			_ = os.RemoveAll(dir)
			return "", err
		}
		if err := os.WriteFile(dst, []byte(content), 0o644); err != nil {
			_ = os.RemoveAll(dir)
			return "", err
		}
	}
	return dir, nil
}

func matchFileAndCategory(exp ExpectedIssue, pred evidence.Finding) bool {
	if filepath.ToSlash(exp.File) != filepath.ToSlash(pred.Path) {
		return false
	}
	ec := strings.ToLower(exp.Category)
	pc := strings.ToLower(pred.Category)
	if ec == pc {
		return true
	}
	if strings.Contains(ec, "security") && strings.Contains(pc, "security") {
		return true
	}
	if strings.Contains(ec, "api") && (strings.Contains(pc, "api") || strings.Contains(pc, "contract")) {
		return true
	}
	return false
}

func abs64(v int64) int64 {
	if v < 0 {
		return -v
	}
	return v
}
