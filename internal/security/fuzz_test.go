package security

import (
	"strings"
	"testing"
)

func FuzzScanPatches(f *testing.F) {
	f.Add("commit 1234567\n+++ b/a.go\n@@ -1,1 +1,2 @@\n+const k = \"AKIAZ9X8C7V6B5N4M3Q2\"\n", "")
	f.Add("diff --git a/b.go b/b.go\n+++ b/b.go\n@@ -1,1 +1,2 @@\n+const p = \"${ENV_VAR}\"\n", "")
	f.Fuzz(func(t *testing.T, patches, headDiff string) {
		findings := ScanPatches(patches, headDiff)
		_ = FormatMarkdownReport(findings)
	})
}

func FuzzMaskSecret(f *testing.F) {
	f.Add("short")
	f.Add("AKIAZ9X8C7V6B5N4M3Q2")
	f.Fuzz(func(t *testing.T, raw string) {
		masked := MaskSecret(raw)
		if len(raw) > 8 && strings.Contains(masked, raw) {
			t.Fatalf("MaskSecret failed to redact %q -> %q", raw, masked)
		}
	})
}
