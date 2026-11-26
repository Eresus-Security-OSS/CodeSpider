// Package config loads and validates runtime configuration for CodeSpider.
package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds all configuration for the 24/7 CodeSpider daemon.
type Config struct {
	ListenAddr string

	GiteaBaseURL       string
	GiteaToken         string
	GiteaWebhookSecret string
	GiteaBotUsername   string
	SkipDraftPRs       bool
	IgnoreBotPRs       bool

	LLMBaseURL string
	LLMAPIKey  string
	LLMModel   string
	LLMTimeout time.Duration

	AgentMaxSteps       int
	AgentMaxTokens      int
	AgentSkillsDir      string
	AgentDefaultSkills  []string
	AgentEnableWrite    bool
	DataDir             string
	Workers             int
	ReconcileInterval   time.Duration
	LogLevel            string
}

// LoadFromEnv reads configuration from environment variables and validates required fields.
func LoadFromEnv() (Config, error) {
	cfg := Config{
		ListenAddr:         getEnv("CODESPIDER_LISTEN_ADDR", ":8080"),
		GiteaBaseURL:       strings.TrimRight(os.Getenv("GITEA_BASE_URL"), "/"),
		GiteaToken:         os.Getenv("GITEA_TOKEN"),
		GiteaWebhookSecret: os.Getenv("GITEA_WEBHOOK_SECRET"),
		GiteaBotUsername:   getEnv("GITEA_BOT_USERNAME", "codespider"),
		SkipDraftPRs:       getEnvBool("SKIP_DRAFT_PRS", true),
		IgnoreBotPRs:       getEnvBool("IGNORE_BOT_PRS", true),
		LLMBaseURL:         strings.TrimRight(getEnv("LLM_BASE_URL", "https://api.openai.com/v1"), "/"),
		LLMAPIKey:          getEnv("LLM_API_KEY", ""),
		LLMModel:           getEnv("LLM_MODEL", "gpt-5"),
		LLMTimeout:         time.Duration(getEnvInt("LLM_TIMEOUT_SECONDS", 120)) * time.Second,
		AgentMaxSteps:      getEnvInt("AGENT_MAX_STEPS", 12),
		AgentMaxTokens:     getEnvInt("AGENT_MAX_TOKENS_PER_RUN", 32000),
		AgentSkillsDir:     getEnv("AGENT_SKILLS_DIR", "./skills"),
		AgentDefaultSkills: splitCSV(getEnv("AGENT_DEFAULT_SKILLS", "security,code-quality")),
		AgentEnableWrite:   getEnvBool("AGENT_ENABLE_WRITE", false),
		DataDir:            getEnv("DATA_DIR", "./data"),
		Workers:            getEnvInt("WORKERS", 2),
		ReconcileInterval:  time.Duration(getEnvInt("RECONCILE_INTERVAL_SECONDS", 300)) * time.Second,
		LogLevel:           strings.ToLower(getEnv("LOG_LEVEL", "info")),
	}

	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// Validate checks that required configuration fields are present and sane.
func (c Config) Validate() error {
	var errs []error
	if c.GiteaBaseURL == "" {
		errs = append(errs, errors.New("GITEA_BASE_URL is required"))
	}
	if c.GiteaToken == "" {
		errs = append(errs, errors.New("GITEA_TOKEN is required"))
	}
	if c.LLMBaseURL == "" {
		errs = append(errs, errors.New("LLM_BASE_URL is required"))
	}
	if c.LLMModel == "" {
		errs = append(errs, errors.New("LLM_MODEL is required"))
	}
	if c.Workers < 1 {
		errs = append(errs, fmt.Errorf("WORKERS must be >= 1, got %d", c.Workers))
	}
	if c.AgentMaxSteps < 1 {
		errs = append(errs, fmt.Errorf("AGENT_MAX_STEPS must be >= 1, got %d", c.AgentMaxSteps))
	}
	return errors.Join(errs...)
}

func getEnv(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func getEnvInt(key string, fallback int) int {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	return n
}

func getEnvBool(key string, fallback bool) bool {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return fallback
	}
	return b
}

func splitCSV(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if s := strings.TrimSpace(p); s != "" {
			out = append(out, s)
		}
	}
	return out
}
