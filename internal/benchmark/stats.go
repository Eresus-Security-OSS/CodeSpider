package benchmark

import (
	"fmt"
	"math"
	"strings"

	"github.com/Eresus-Security-OSS/CodeSpider/internal/evidence"
)

// ConfidenceInterval represents a lower/upper bound in [0, 1].
type ConfidenceInterval struct {
	Lower float64 `json:"lower"`
	Upper float64 `json:"upper"`
}

// CategorySummary tracks per-category TP/FP/FN counts.
type CategorySummary struct {
	TruePositives  int     `json:"true_positives"`
	FalsePositives int     `json:"false_positives"`
	FalseNegatives int     `json:"false_negatives"`
	Precision      float64 `json:"precision"`
	Recall         float64 `json:"recall"`
}

// WilsonInterval computes a Wilson score confidence interval (use z=1.96 for 95% CI).
func WilsonInterval(successes, total int, z float64) ConfidenceInterval {
	if total <= 0 {
		return ConfidenceInterval{}
	}
	if z <= 0 {
		z = 1.96
	}
	n := float64(total)
	p := float64(successes) / n
	z2 := z * z
	denom := 1 + z2/n
	center := (p + z2/(2*n)) / denom
	half := (z * math.Sqrt((p*(1-p)+z2/(4*n))/n)) / denom
	low := center - half
	if low < 0 {
		low = 0
	}
	high := center + half
	if high > 1 {
		high = 1
	}
	return ConfidenceInterval{Lower: low, Upper: high}
}

// ValidateDataset verifies unique IDs and non-empty diffs/files within a split.
func ValidateDataset(cases []Case) error {
	seen := make(map[string]bool, len(cases))
	for i, c := range cases {
		if strings.TrimSpace(c.ID) == "" {
			return fmt.Errorf("case %d missing id", i)
		}
		if seen[c.ID] {
			return fmt.Errorf("duplicate case id %q", c.ID)
		}
		seen[c.ID] = true
		if strings.TrimSpace(c.Diff) == "" && len(c.Files) == 0 {
			return fmt.Errorf("case %q has neither diff nor files", c.ID)
		}
	}
	return nil
}

// CheckNoSplitLeakage ensures no case IDs overlap across dev/validation/holdout splits.
func CheckNoSplitLeakage(splits map[string][]Case) error {
	owner := make(map[string]string)
	for splitName, cases := range splits {
		for _, c := range cases {
			if prev, exists := owner[c.ID]; exists && prev != splitName {
				return fmt.Errorf("benchmark leakage: case %q appears in both %q and %q", c.ID, prev, splitName)
			}
			owner[c.ID] = splitName
		}
	}
	return nil
}

// PredictorFunc is an optional callback for llm-only or hybrid benchmark mode evaluation.
type PredictorFunc func(c Case) []evidence.Finding

// CompareModes runs deterministic-only, llm-only (when provided), and hybrid modes over the same cases.
func CompareModes(datasetName string, cases []Case, llmPredictor PredictorFunc) ([]Summary, error) {
	detSum, err := RunWithMode(datasetName, "deterministic-only", cases, nil)
	if err != nil {
		return nil, err
	}
	out := []Summary{detSum}
	if llmPredictor != nil {
		llmSum, err := RunWithMode(datasetName, "llm-only", cases, llmPredictor)
		if err != nil {
			return nil, err
		}
		hybSum, err := RunWithMode(datasetName, "hybrid", cases, llmPredictor)
		if err != nil {
			return nil, err
		}
		out = append(out, llmSum, hybSum)
	}
	return out, nil
}
