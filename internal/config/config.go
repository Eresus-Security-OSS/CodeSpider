// Package config loads and validates YAML runtime configuration for CodeSpider.
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

	AgentMaxSteps      int
	AgentMaxTokens     int
	AgentSkillsDir     string
	AgentDefaultSkills []string
	AgentEnableWrite   bool
	DataDir            string
	Workers            int
	ReconcileInterval  time.Duration
	LogLevel           string
}

// Default returns a Config populated with default values.
func Default() Config {
	return Config{
		ListenAddr:         ":8080",
		GiteaBotUsername:   "codespider",
		SkipDraftPRs:       true,
		IgnoreBotPRs:       true,
		LLMBaseURL:         "https://api.openai.com/v1",
		LLMModel:           "gpt-5",
		LLMTimeout:         120 * time.Second,
		AgentMaxSteps:      12,
		AgentMaxTokens:     32000,
		AgentSkillsDir:     "./skills",
		AgentDefaultSkills: []string{"security", "code-quality", "testing"},
		AgentEnableWrite:   false,
		DataDir:            "./data",
		Workers:            2,
		ReconcileInterval:  300 * time.Second,
		LogLevel:           "info",
	}
}

// ResolvePath determines which YAML config file to load based on -f flag,
// CODESPIDER_CONFIG_PATH environment variable, or default filenames.
func ResolvePath(flagPath string) string {
	if p := strings.TrimSpace(flagPath); p != "" {
		return p
	}
	if p := strings.TrimSpace(os.Getenv("CODESPIDER_CONFIG_PATH")); p != "" {
		return p
	}
	for _, candidate := range []string{"codespider.yaml", "codespider.yml"} {
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	return "codespider.yaml"
}

// LoadFromFile reads YAML configuration from path and validates required fields.
func LoadFromFile(path string) (Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config %s: %w", path, err)
	}

	cfg := Default()
	if err := parseYAML(string(raw), &cfg); err != nil {
		return Config{}, fmt.Errorf("parse config %s: %w", path, err)
	}

	cfg.GiteaBaseURL = strings.TrimRight(cfg.GiteaBaseURL, "/")
	cfg.LLMBaseURL = strings.TrimRight(cfg.LLMBaseURL, "/")
	cfg.LogLevel = strings.ToLower(strings.TrimSpace(cfg.LogLevel))

	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// Validate checks that required configuration fields are present and sane.
func (c Config) Validate() error {
	var errs []error
	if c.GiteaBaseURL == "" {
		errs = append(errs, errors.New("gitea.base_url is required"))
	}
	if c.GiteaToken == "" {
		errs = append(errs, errors.New("gitea.token is required"))
	}
	if c.LLMBaseURL == "" {
		errs = append(errs, errors.New("llm.base_url is required"))
	}
	if c.LLMModel == "" {
		errs = append(errs, errors.New("llm.model is required"))
	}
	if c.Workers < 1 {
		errs = append(errs, fmt.Errorf("daemon.workers must be >= 1, got %d", c.Workers))
	}
	if c.AgentMaxSteps < 1 {
		errs = append(errs, fmt.Errorf("agent.max_steps must be >= 1, got %d", c.AgentMaxSteps))
	}
	return errors.Join(errs...)
}

func parseYAML(content string, cfg *Config) error {
	lines := strings.Split(content, "\n")
	section := ""
	inListKey := ""
	defaultSkillsCleared := false

	for lineNo, rawLine := range lines {
		cleaned := stripComment(rawLine)
		trimmed := strings.TrimSpace(cleaned)
		if trimmed == "" || trimmed == "---" {
			continue
		}

		indent := countLeadingSpaces(cleaned)

		// List item under current section/key (e.g. "    - security")
		if strings.HasPrefix(trimmed, "- ") {
			if inListKey == "agent.default_skills" {
				if !defaultSkillsCleared {
					cfg.AgentDefaultSkills = nil
					defaultSkillsCleared = true
				}
				item := unquoteAndExpand(strings.TrimSpace(strings.TrimPrefix(trimmed, "- ")))
				if item != "" {
					cfg.AgentDefaultSkills = append(cfg.AgentDefaultSkills, item)
				}
				continue
			}
			return fmt.Errorf("line %d: unexpected list item %q", lineNo+1, trimmed)
		}

		key, val, ok := strings.Cut(trimmed, ":")
		if !ok {
			return fmt.Errorf("line %d: expected key: value, got %q", lineNo+1, trimmed)
		}
		key = strings.ToLower(strings.TrimSpace(key))
		val = strings.TrimSpace(val)
		inListKey = ""

		// Top-level section header (indent == 0, empty value)
		if indent == 0 && val == "" {
			section = key
			continue
		}
		if indent == 0 {
			section = ""
		}

		fullKey := key
		if section != "" {
			fullKey = section + "." + key
		}

		if val == "" {
			if fullKey == "agent.default_skills" {
				inListKey = fullKey
				if !defaultSkillsCleared {
					cfg.AgentDefaultSkills = nil
					defaultSkillsCleared = true
				}
			}
			continue
		}

		if err := applyField(fullKey, val, cfg); err != nil {
			return fmt.Errorf("line %d (%s): %w", lineNo+1, fullKey, err)
		}
	}
	return nil
}

func applyField(fullKey, rawVal string, cfg *Config) error {
	val := unquoteAndExpand(rawVal)
	switch fullKey {
	case "server.listen_addr", "listen_addr":
		cfg.ListenAddr = val
	case "gitea.base_url":
		cfg.GiteaBaseURL = val
	case "gitea.token":
		cfg.GiteaToken = val
	case "gitea.webhook_secret":
		cfg.GiteaWebhookSecret = val
	case "gitea.bot_username":
		cfg.GiteaBotUsername = val
	case "gitea.skip_draft_prs":
		b, err := strconv.ParseBool(val)
		if err != nil {
			return err
		}
		cfg.SkipDraftPRs = b
	case "gitea.ignore_bot_prs":
		b, err := strconv.ParseBool(val)
		if err != nil {
			return err
		}
		cfg.IgnoreBotPRs = b
	case "llm.base_url":
		cfg.LLMBaseURL = val
	case "llm.api_key":
		cfg.LLMAPIKey = val
	case "llm.model":
		cfg.LLMModel = val
	case "llm.timeout_seconds":
		n, err := strconv.Atoi(val)
		if err != nil {
			return err
		}
		cfg.LLMTimeout = time.Duration(n) * time.Second
	case "agent.max_steps":
		n, err := strconv.Atoi(val)
		if err != nil {
			return err
		}
		cfg.AgentMaxSteps = n
	case "agent.max_tokens_per_run":
		n, err := strconv.Atoi(val)
		if err != nil {
			return err
		}
		cfg.AgentMaxTokens = n
	case "agent.skills_dir":
		cfg.AgentSkillsDir = val
	case "agent.default_skills":
		cfg.AgentDefaultSkills = parseInlineList(rawVal)
	case "agent.enable_write":
		b, err := strconv.ParseBool(val)
		if err != nil {
			return err
		}
		cfg.AgentEnableWrite = b
	case "daemon.data_dir", "data_dir":
		cfg.DataDir = val
	case "daemon.workers", "workers":
		n, err := strconv.Atoi(val)
		if err != nil {
			return err
		}
		cfg.Workers = n
	case "daemon.reconcile_interval_seconds":
		n, err := strconv.Atoi(val)
		if err != nil {
			return err
		}
		cfg.ReconcileInterval = time.Duration(n) * time.Second
	case "daemon.log_level", "log_level":
		cfg.LogLevel = val
	}
	return nil
}

func parseInlineList(raw string) []string {
	raw = strings.TrimSpace(raw)
	raw = strings.TrimPrefix(raw, "[")
	raw = strings.TrimSuffix(raw, "]")
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if s := unquoteAndExpand(strings.TrimSpace(p)); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func unquoteAndExpand(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			s = s[1 : len(s)-1]
		}
	}
	return expandEnvBraced(s)
}

// expandEnvBraced expands only ${VAR} placeholders, leaving literal $ characters intact.
func expandEnvBraced(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		if i+2 < len(s) && s[i] == '$' && s[i+1] == '{' {
			if end := strings.IndexByte(s[i+2:], '}'); end != -1 {
				name := s[i+2 : i+2+end]
				b.WriteString(os.Getenv(name))
				i = i + 2 + end + 1
				continue
			}
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

func stripComment(line string) string {
	inSingle := false
	inDouble := false
	for i := 0; i < len(line); i++ {
		c := line[i]
		if c == '\'' && !inDouble {
			inSingle = !inSingle
		} else if c == '"' && !inSingle {
			inDouble = !inDouble
		} else if c == '#' && !inSingle && !inDouble {
			if i == 0 || line[i-1] == ' ' || line[i-1] == '\t' {
				return line[:i]
			}
		}
	}
	return line
}

func countLeadingSpaces(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] == ' ' {
			n++
		} else if s[i] == '\t' {
			n += 2
		} else {
			break
		}
	}
	return n
}
