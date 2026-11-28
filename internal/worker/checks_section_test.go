package worker

import (
	"strings"
	"testing"

	"github.com/Eresus-Security-OSS/CodeSpider/internal/repoconfig"
)

func TestWriteChecksSectionFlagsFailuresAndEscapesCells(t *testing.T) {
	var b strings.Builder
	writeChecksSection(&b, nil)
	if b.Len() != 0 {
		t.Fatalf("no checks must render nothing, got %q", b.String())
	}

	writeChecksSection(&b, []repoconfig.CheckResult{
		{Name: "PR title format", Passed: true, Detail: "ok"},
		{Name: "PR size", Passed: false, Detail: "500 | 400 `lines`"},
	})
	out := b.String()
	if !strings.Contains(out, "| PR title format | pass | ok |") {
		t.Fatalf("missing pass row:\n%s", out)
	}
	if !strings.Contains(out, "| PR size | **warn** | 500 / 400 'lines' |") {
		t.Fatalf("expected warn row with sanitized detail:\n%s", out)
	}
}
