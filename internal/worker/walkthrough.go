package worker

import (
	"fmt"
	"strings"

	"github.com/Eresus-Security-OSS/CodeSpider/internal/repoconfig"
)

const maxWalkthroughFiles = 30

type reviewEffort struct {
	Level   int
	Label   string
	Minutes int
}

// estimateReviewEffort derives a coarse 1-5 reviewer-effort score from diff size.
// It is a size heuristic, not a model judgment.
func estimateReviewEffort(files, changedLines int) reviewEffort {
	var level int
	switch {
	case changedLines <= 20:
		level = 1
	case changedLines <= 100:
		level = 2
	case changedLines <= 400:
		level = 3
	case changedLines <= 1000:
		level = 4
	default:
		level = 5
	}
	if files > 15 && level < 5 {
		level++
	}
	table := [...]reviewEffort{
		{1, "Trivial", 5},
		{2, "Light", 10},
		{3, "Moderate", 25},
		{4, "Heavy", 45},
		{5, "Very heavy", 90},
	}
	return table[level-1]
}

// sanitizeTableCell makes an untrusted path safe inside a Markdown table code span.
func sanitizeTableCell(s string) string {
	r := strings.NewReplacer("`", "'", "|", "/", "\n", " ", "\r", " ")
	return r.Replace(s)
}

// writeChangeOverview appends the review-effort estimate and a collapsible per-file change table.
func writeChangeOverview(b *strings.Builder, diff string) {
	stats := repoconfig.DiffFileStats(diff)
	if len(stats) == 0 {
		return
	}
	var added, removed int
	for _, s := range stats {
		added += s.Added
		removed += s.Removed
	}
	effort := estimateReviewEffort(len(stats), added+removed)
	fmt.Fprintf(b, "- **Change size:** `%d` file(s), `+%d` / `-%d` lines | **Estimated review effort:** `%d/5 (%s)`, ~%d min\n\n",
		len(stats), added, removed, effort.Level, effort.Label, effort.Minutes)

	b.WriteString("<details>\n<summary>Changed files</summary>\n\n| File | Change |\n| :--- | :--- |\n")
	for i, s := range stats {
		if i >= maxWalkthroughFiles {
			fmt.Fprintf(b, "| _… and %d more file(s)_ | |\n", len(stats)-maxWalkthroughFiles)
			break
		}
		change := fmt.Sprintf("+%d / -%d", s.Added, s.Removed)
		if s.Binary {
			change = "binary"
		}
		fmt.Fprintf(b, "| `%s` | %s |\n", sanitizeTableCell(s.Path), change)
	}
	b.WriteString("\n</details>\n\n")
}
