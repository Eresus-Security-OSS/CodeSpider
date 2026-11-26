package opsintel

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCorrelatorRedactsAndGatesLLMSharing(t *testing.T) {
	p := filepath.Join(t.TempDir(), "telemetry.json")
	raw := `[{"source":"sentry","repo":"acme/api","path_prefix":"internal/auth","metric":"exception","summary":"panic with Bearer ghp_1234567890abcdef1234"}]`
	if err := os.WriteFile(p, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}

	// Default allowLLMSharing=false must return annotations for deterministic summary but empty LLM prompt.
	cOff, err := Load(p, false)
	if err != nil {
		t.Fatal(err)
	}
	anns, prompt := cOff.Correlate("acme/api", []string{"internal/auth/jwt.go"})
	if len(anns) != 1 {
		t.Fatalf("expected 1 annotation, got %+v", anns)
	}
	if strings.Contains(anns[0].Summary, "ghp_") {
		t.Fatalf("expected token to be redacted in annotation: %q", anns[0].Summary)
	}
	if prompt != "" {
		t.Fatalf("expected empty LLM prompt when allowLLMSharing=false, got %q", prompt)
	}

	// Explicit allowLLMSharing=true populates redacted LLM prompt.
	cOn, err := Load(p, true)
	if err != nil {
		t.Fatal(err)
	}
	_, promptOn := cOn.Correlate("acme/api", []string{"internal/auth/jwt.go"})
	if !strings.Contains(promptOn, "[sentry]") || strings.Contains(promptOn, "ghp_") {
		t.Fatalf("unexpected LLM prompt: %q", promptOn)
	}
}
