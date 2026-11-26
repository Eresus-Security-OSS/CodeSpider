package benchmark

import (
	"path/filepath"
	"testing"

	"github.com/Eresus-Security-OSS/CodeSpider/internal/evidence"
)

func TestRunOfflineBenchmarkSuite(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "benchmarks", "local_suite.jsonl")
	cases, err := LoadJSONL(path)
	if err != nil {
		t.Fatalf("LoadJSONL failed: %v", err)
	}
	if len(cases) != 8 {
		t.Fatalf("expected 8 cases, got %d", len(cases))
	}

	sum, err := RunOffline("local_suite", cases)
	if err != nil {
		t.Fatalf("RunOffline failed: %v", err)
	}
	if sum.Recall < 0.9 || sum.Precision < 0.9 || sum.FalsePositiveRate != 0 {
		t.Fatalf("unexpected offline benchmark metrics: %+v", sum)
	}
}

func TestSplitBenchmarksNoLeakageAndWilsonCIs(t *testing.T) {
	splits := map[string][]Case{}
	for _, name := range []string{"dev", "validation", "holdout"} {
		p := filepath.Join("..", "..", "testdata", "benchmarks", name+".jsonl")
		cases, err := LoadJSONL(p)
		if err != nil {
			t.Fatalf("LoadJSONL(%s): %v", name, err)
		}
		if len(cases) < 20 {
			t.Fatalf("expected >= 20 cases in %s, got %d", name, len(cases))
		}
		if err := ValidateDataset(cases); err != nil {
			t.Fatalf("ValidateDataset(%s): %v", name, err)
		}
		splits[name] = cases

		sum, err := RunOffline(p, cases)
		if err != nil {
			t.Fatalf("RunOffline(%s): %v", name, err)
		}
		if sum.Precision < 0.9 || sum.Recall < 0.9 || sum.FalsePositiveRate > 0.05 {
			t.Fatalf("unexpected %s split metrics: %+v", name, sum)
		}
		if sum.PrecisionCI.Upper <= sum.PrecisionCI.Lower || sum.RecallCI.Upper <= sum.RecallCI.Lower {
			t.Fatalf("expected non-degenerate 95%% Wilson CIs for %s, got P=%+v R=%+v", name, sum.PrecisionCI, sum.RecallCI)
		}
	}
	if err := CheckNoSplitLeakage(splits); err != nil {
		t.Fatalf("split leakage detected: %v", err)
	}

	modes, err := CompareModes("dev", splits["dev"][:3], func(c Case) []evidence.Finding { return nil })
	if err != nil || len(modes) != 3 {
		t.Fatalf("CompareModes failed: len=%d err=%v", len(modes), err)
	}
}
