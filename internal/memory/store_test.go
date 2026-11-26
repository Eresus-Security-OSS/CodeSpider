package memory

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Eresus-Security-OSS/CodeSpider/internal/evidence"
)

func TestMemoryAuthorizationFilteringIncidentsAndSimulation(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	// Untrusted caller cannot mutate memory
	err = st.RecordFeedback(false, FeedbackRecord{Fingerprint: "fp1", Status: "false_positive", RecordedBy: "forker"})
	if !errors.Is(err, ErrUnauthorizedMemoryMutation) {
		t.Fatalf("expected ErrUnauthorizedMemoryMutation, got %v", err)
	}

	// Authorized collaborator suppresses fp1 and records an incident
	if err := st.RecordFeedback(true, FeedbackRecord{
		Fingerprint: "fp1",
		Repo:        "acme/api",
		Status:      "false_positive",
		RecordedBy:  "alice",
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertRule(true, PolicyRule{
		ID:          "R-1",
		Scope:       "repo",
		Repo:        "acme/api",
		Instruction: "Always validate tenant ID",
		ApprovedBy:  "alice",
	}); err != nil {
		t.Fatal(err)
	}
	expired := time.Now().UTC().Add(-time.Hour)
	if err := st.UpsertRule(true, PolicyRule{
		ID:          "R-EXP",
		Scope:       "repo",
		Repo:        "acme/api",
		Instruction: "Old expired rule",
		ApprovedBy:  "alice",
		ExpiresAt:   &expired,
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.RecordIncident(true, IncidentRecord{
		ID:         "INC-42",
		Repo:       "acme/api",
		PathPrefix: "internal/billing/",
		Summary:    "Deadlock during retry storm in 2026-09",
	}); err != nil {
		t.Fatal(err)
	}

	findings := []evidence.Finding{
		{Fingerprint: "fp1", Path: "a.go", Body: "noise"},
		{Fingerprint: "fp2", Path: "internal/billing/pay.go", Severity: "critical", State: evidence.StateStaticallySupported, Body: "real"},
	}
	kept, suppressed := st.FilterFindings("acme/api", findings)
	if suppressed != 1 || len(kept) != 1 || kept[0].Fingerprint != "fp2" {
		t.Fatalf("unexpected filter result: suppressed=%d kept=%+v", suppressed, kept)
	}

	ctxText := st.RelevantContext("acme/api", []string{"internal/billing/pay.go"})
	if !strings.Contains(ctxText, "INC-42") || !strings.Contains(ctxText, "R-1") || strings.Contains(ctxText, "R-EXP") {
		t.Fatalf("unexpected memory context:\n%s", ctxText)
	}

	sim := SimulatePolicy(PolicyRule{Pattern: "billing", Severity: "suppress"}, findings)
	if sim.MatchedCount != 1 || len(sim.SuppressedIDs) != 1 {
		t.Fatalf("unexpected simulation result: %+v", sim)
	}

	// Delete works for authorized caller
	removed, err := st.Delete(true, "R-1")
	if err != nil || !removed {
		t.Fatalf("expected Delete(R-1) to succeed, removed=%v err=%v", removed, err)
	}
}
