package security

import (
	"strings"
	"testing"
)

func TestScanPatchesDetectsHistoryOnlyAndHeadSecrets(t *testing.T) {
	awsSecret := "AKIA" + "Z9X8C7V6B5N4M3Q2"
	commitPatches := strings.Join([]string{
		"commit 1111111111111111111111111111111111111111",
		"+++ b/config.go",
		"@@ -1,2 +1,4 @@",
		"+const awsKey = \"" + awsSecret + "\"",
		"+const placeholder = \"${ENV_API_KEY}\"",
		"commit 2222222222222222222222222222222222222222",
		"+++ b/config.go",
		"@@ -1,4 +1,2 @@",
		"-const awsKey = \"" + awsSecret + "\"",
	}, "\n")

	// HEAD diff no longer contains the AWS key because commit 2 removed it
	headDiff := strings.Join([]string{
		"diff --git a/config.go b/config.go",
		"+++ b/config.go",
		"@@ -1,2 +1,3 @@",
		"+const placeholder = \"${ENV_API_KEY}\"",
	}, "\n")

	findings := ScanPatches(commitPatches, headDiff)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Kind != "AWS Access Key" || !f.InHistoryOnly {
		t.Fatalf("expected history-only AWS finding, got %+v", f)
	}
	if strings.Contains(f.MaskedPreview, awsSecret) {
		t.Fatalf("secret must be masked, got %q", f.MaskedPreview)
	}

	report := FormatMarkdownReport(findings)
	if !strings.Contains(report, "squash/rebase recommended") || strings.Contains(report, awsSecret) {
		t.Fatalf("unexpected formatted report:\n%s", report)
	}
}
