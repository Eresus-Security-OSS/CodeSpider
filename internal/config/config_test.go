package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadFromFile(t *testing.T) {
	t.Setenv("TEST_LLM_KEY", "sk-env-secret")

	yamlContent := `
server:
  listen_addr: ":9090"

gitea:
  base_url: "https://gitea.internal/"
  token: "gt-token-123"
  webhook_secret: "wh-sec"
  bot_username: "spiderbot"
  skip_draft_prs: false
  ignore_bot_prs: true

llm:
  base_url: "https://litellm.internal/v1/"
  api_key: "${TEST_LLM_KEY}"
  model: "claude-sonnet"
  timeout_seconds: 60

agent:
  max_steps: 20
  max_tokens_per_run: 64000
  skills_dir: "/etc/codespider/skills"
  default_skills:
    - security
    - testing
  enable_write: true

daemon:
  data_dir: "/var/lib/codespider"
  workers: 4
  reconcile_interval_seconds: 120
  log_level: "DEBUG"
`
	cfgPath := filepath.Join(t.TempDir(), "codespider.yaml")
	if err := os.WriteFile(cfgPath, []byte(yamlContent), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadFromFile(cfgPath)
	if err != nil {
		t.Fatalf("LoadFromFile failed: %v", err)
	}

	if cfg.ListenAddr != ":9090" {
		t.Fatalf("unexpected ListenAddr: %q", cfg.ListenAddr)
	}
	if cfg.GiteaBaseURL != "https://gitea.internal" || cfg.GiteaToken != "gt-token-123" || cfg.SkipDraftPRs {
		t.Fatalf("unexpected gitea config: %+v", cfg)
	}
	if cfg.LLMBaseURL != "https://litellm.internal/v1" || cfg.LLMAPIKey != "sk-env-secret" || cfg.LLMModel != "claude-sonnet" || cfg.LLMTimeout != 60*time.Second {
		t.Fatalf("unexpected llm config: %+v", cfg)
	}
	if cfg.AgentMaxSteps != 20 || cfg.AgentMaxTokens != 64000 || !cfg.AgentEnableWrite {
		t.Fatalf("unexpected agent config: %+v", cfg)
	}
	if len(cfg.AgentDefaultSkills) != 2 || cfg.AgentDefaultSkills[0] != "security" || cfg.AgentDefaultSkills[1] != "testing" {
		t.Fatalf("unexpected default skills: %#v", cfg.AgentDefaultSkills)
	}
	if cfg.Workers != 4 || cfg.LogLevel != "debug" || cfg.ReconcileInterval != 120*time.Second {
		t.Fatalf("unexpected daemon config: %+v", cfg)
	}
}

func TestResolvePathPrecedence(t *testing.T) {
	t.Setenv("CODESPIDER_CONFIG_PATH", "/env/codespider.yaml")
	if got := ResolvePath("/flag/codespider.yaml"); got != "/flag/codespider.yaml" {
		t.Fatalf("expected flag to win, got %q", got)
	}
	if got := ResolvePath(""); got != "/env/codespider.yaml" {
		t.Fatalf("expected env to win, got %q", got)
	}
	t.Setenv("CODESPIDER_CONFIG_PATH", "")
	if got := ResolvePath(""); got != "codespider.yaml" {
		t.Fatalf("expected default codespider.yaml, got %q", got)
	}
}

func TestLoadFromFileValidationError(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "bad.yaml")
	if err := os.WriteFile(cfgPath, []byte("server:\n  listen_addr: \":8080\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := LoadFromFile(cfgPath)
	if err == nil || !strings.Contains(err.Error(), "gitea.base_url is required") || !strings.Contains(err.Error(), "gitea.token is required") {
		t.Fatalf("expected validation error, got: %v", err)
	}
}
