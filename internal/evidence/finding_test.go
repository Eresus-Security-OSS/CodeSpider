package evidence

import (
	"strings"
	"testing"
)

func TestEvidenceStatesAndTransitions(t *testing.T) {
	f := Finding{
		RuleID:   "CS-SEC-001",
		Category: "security",
		Path:     "internal/auth.go",
		EndLine:  42,
		Severity: "critical",
		State:    StateCandidate,
		Body:     "Missing HMAC check",
	}
	f.Fingerprint = ComputeFingerprint(f.RuleID, f.Category, f.Path, "Verify")
	if len(f.Fingerprint) != 16 {
		t.Fatalf("expected 16-char fingerprint, got %q", f.Fingerprint)
	}

	// Unsuccessful reproduction -> inconclusive (never refuted)
	f.ApplyTestOutcome(true, false, true, "")
	if f.State != StateInconclusive {
		t.Fatalf("expected StateInconclusive when test passes on head, got %s", f.State)
	}

	// Base passes, Head fails -> differentially_reproduced
	f.ApplyTestOutcome(true, true, true, "")
	if f.State != StateDifferentiallyReproduced || f.PreExisting {
		t.Fatalf("expected regression StateDifferentiallyReproduced, got %+v", f)
	}

	// Both fail -> pre-existing
	f2 := Finding{State: StateCandidate}
	f2.ApplyTestOutcome(false, true, true, "")
	if f2.State != StateTestReproduced || !f2.PreExisting {
		t.Fatalf("expected pre-existing StateTestReproduced, got %+v", f2)
	}

	rendered := f.RenderInlineBody()
	if !strings.Contains(rendered, "[DIFFERENTIALLY REPRODUCED]") || strings.Contains(rendered, "BLUE-TEAM VERIFIED") {
		t.Fatalf("unexpected rendered body:\n%s", rendered)
	}
}
