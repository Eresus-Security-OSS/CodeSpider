package worker

import (
	"strings"
	"testing"
)

func TestEstimateReviewEffortBuckets(t *testing.T) {
	cases := []struct {
		files, lines, level int
	}{
		{1, 5, 1},
		{2, 100, 2},
		{3, 101, 3},
		{4, 1000, 4},
		{4, 1001, 5},
		{20, 10, 2}, // many files bump the level by one
		{20, 5000, 5},
	}
	for _, c := range cases {
		if got := estimateReviewEffort(c.files, c.lines).Level; got != c.level {
			t.Errorf("files=%d lines=%d: want level %d, got %d", c.files, c.lines, c.level, got)
		}
	}
}

func TestWriteChangeOverviewSanitizesPathsAndCapsRows(t *testing.T) {
	var diff strings.Builder
	diff.WriteString("diff --git a/evil`|x.go b/evil`|x.go\n--- a/evil`|x.go\n+++ b/evil`|x.go\n@@ -1 +1 @@\n-old\n+new\n")
	for i := range maxWalkthroughFiles + 5 {
		diff.WriteString("diff --git a/f" + strings.Repeat("x", i) + ".go b/f" + strings.Repeat("x", i) + ".go\n@@ -0,0 +1 @@\n+line\n")
	}

	var b strings.Builder
	writeChangeOverview(&b, diff.String())
	out := b.String()

	if !strings.Contains(out, "| `evil'/x.go` | +1 / -1 |") {
		t.Fatalf("expected sanitized path row, got:\n%s", out)
	}
	if !strings.Contains(out, "… and 6 more file(s)") {
		t.Fatalf("expected row cap marker, got:\n%s", out)
	}
	if !strings.Contains(out, "Estimated review effort") || !strings.Contains(out, "<details>") {
		t.Fatalf("expected effort line and collapsible table, got:\n%s", out)
	}

	var empty strings.Builder
	writeChangeOverview(&empty, "")
	if empty.Len() != 0 {
		t.Fatalf("expected no output for empty diff, got %q", empty.String())
	}
}
