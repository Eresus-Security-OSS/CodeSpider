package store

import (
	"testing"
	"time"
)

func TestStorePersistenceAndQueries(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	prKey := PRKey("acme", "api", 7)
	if st.IsAlreadyReviewed(prKey, "sha1") {
		t.Fatal("expected unreviewed initially")
	}

	err = st.RecordRun(RunRecord{
		PRKey:          prKey,
		Kind:           "pr_review",
		HeadSHA:        "sha1",
		StepsUsed:      3,
		TokensUsed:     450,
		InlineComments: 2,
		DurationMs:     1200,
		Status:         "success",
		FinishedAt:     time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("RecordRun failed: %v", err)
	}

	if !st.IsAlreadyReviewed(prKey, "sha1") {
		t.Fatal("expected sha1 to be marked reviewed")
	}
	if got := st.LastReviewedSHA(prKey); got != "sha1" {
		t.Fatalf("expected LastReviewedSHA sha1, got %q", got)
	}
	if st.ReviewedPRCount() != 1 {
		t.Fatalf("expected ReviewedPRCount 1, got %d", st.ReviewedPRCount())
	}

	// Re-open from disk and verify durability
	st2, err := Open(dir)
	if err != nil {
		t.Fatalf("re-open failed: %v", err)
	}
	if !st2.IsAlreadyReviewed(prKey, "sha1") {
		t.Fatal("expected persisted SHA across reopen")
	}
	runs := st2.RecentRuns()
	if len(runs) != 1 || runs[0].DurationMs != 1200 {
		t.Fatalf("unexpected persisted runs: %+v", runs)
	}
}
