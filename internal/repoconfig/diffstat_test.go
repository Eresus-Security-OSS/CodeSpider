package repoconfig

import "testing"

func TestDiffFileStatsCountsHunkLinesOnly(t *testing.T) {
	diff := "diff --git a/a.go b/a.go\n" +
		"index 111..222 100644\n" +
		"--- a/a.go\n" +
		"+++ b/a.go\n" +
		"@@ -1,3 +1,3 @@\n" +
		" keep\n" +
		"--- removed line that begins with dashes\n" +
		"+++ added line that begins with pluses\n" +
		"+new\n" +
		"diff --git a/img.png b/img.png\n" +
		"Binary files a/img.png and b/img.png differ\n"

	stats := DiffFileStats(diff)
	if len(stats) != 2 {
		t.Fatalf("expected 2 files, got %+v", stats)
	}
	if stats[0].Path != "a.go" || stats[0].Added != 2 || stats[0].Removed != 1 {
		t.Fatalf("unexpected stats for a.go: %+v", stats[0])
	}
	if stats[1].Path != "img.png" || !stats[1].Binary || stats[1].Added != 0 {
		t.Fatalf("unexpected stats for img.png: %+v", stats[1])
	}
	if DiffFileStats("") != nil {
		t.Fatal("expected nil for empty diff")
	}
}
