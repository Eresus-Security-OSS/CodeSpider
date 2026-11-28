package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func loadDaemonYAML(t *testing.T, daemon string) (Config, error) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "codespider.yaml")
	body := "gitea:\n  base_url: \"https://g\"\n  token: \"t\"\nllm:\n  base_url: \"https://l/v1\"\n  model: \"m\"\n" + daemon
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return LoadFromFile(p)
}

func TestUpdateCheckIsOffByDefaultAndParsesHours(t *testing.T) {
	cfg, err := loadDaemonYAML(t, "daemon:\n  workers: 1\n")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.UpdateCheckInterval != 0 {
		t.Fatalf("outbound update check must be off by default, got %s", cfg.UpdateCheckInterval)
	}

	cfg, err = loadDaemonYAML(t, "daemon:\n  update_check_hours: 24\n")
	if err != nil || cfg.UpdateCheckInterval != 24*time.Hour {
		t.Fatalf("expected 24h, got %s err=%v", cfg.UpdateCheckInterval, err)
	}

	for _, bad := range []string{"-1", "100000", "abc"} {
		if _, err := loadDaemonYAML(t, "daemon:\n  update_check_hours: "+bad+"\n"); err == nil {
			t.Errorf("update_check_hours %q must be rejected", bad)
		}
	}
}
