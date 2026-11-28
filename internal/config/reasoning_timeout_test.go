package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeYAML writes a config with valid gitea settings followed by body and returns its path.
func writeYAML(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "codespider.yaml")
	full := "gitea:\n  base_url: \"https://g\"\n  token: \"t\"\n" + body
	if err := os.WriteFile(p, []byte(full), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

const llmBlock = "llm:\n  base_url: \"https://l/v1\"\n  model: \"m\"\n"

func TestReasoningEffortAndJobTimeoutDefaultsKeepTodaysBehavior(t *testing.T) {
	cfg, err := LoadFromFile(writeYAML(t, llmBlock))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LLMReasoningEffort != "" || cfg.AgentJobTimeout != 5*time.Minute {
		t.Fatalf("unexpected defaults: effort=%q timeout=%s", cfg.LLMReasoningEffort, cfg.AgentJobTimeout)
	}
}

func TestReasoningEffortAndJobTimeoutParse(t *testing.T) {
	cfg, err := LoadFromFile(writeYAML(t, llmBlock+"  reasoning_effort: \"None\"\nagent:\n  job_timeout_seconds: 900\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LLMReasoningEffort != "none" || cfg.AgentJobTimeout != 15*time.Minute {
		t.Fatalf("expected normalized effort and 15m timeout, got %q %s", cfg.LLMReasoningEffort, cfg.AgentJobTimeout)
	}
}

func TestReasoningEffortAndJobTimeoutRejectInvalidValues(t *testing.T) {
	for name, body := range map[string]string{
		"unknown effort":  llmBlock + "  reasoning_effort: \"extreme\"\n",
		"timeout too low": llmBlock + "agent:\n  job_timeout_seconds: 5\n",
		"timeout too big": llmBlock + "agent:\n  job_timeout_seconds: 99999\n",
		"timeout nonnum":  llmBlock + "agent:\n  job_timeout_seconds: soon\n",
	} {
		if _, err := LoadFromFile(writeYAML(t, body)); err == nil {
			t.Errorf("%s must be rejected", name)
		}
	}
}
