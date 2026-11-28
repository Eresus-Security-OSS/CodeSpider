// Package config loads and validates YAML runtime configuration for CodeSpider.
package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds all configuration for the 24/7 CodeSpider daemon.
type Config struct {
	ListenAddr    string
	AdminToken    string
	ForgeProvider string
	ForgeRepos    []string

	GiteaBaseURL              string
	GiteaToken                string
	GiteaWebhookSecret        string
	GiteaBotUsername          string
	GiteaRepos                []string
	AllowUnsignedWebhooks     bool
	AllowSameOwnerCrossRepo   bool
	CrossRepoAllowlist        []string
	SkipDraftPRs              bool
	IgnoreBotPRs              bool
	StickySummary             bool
	RequireCollaboratorForFix bool
	GitHubBaseURL             string
	GitHubToken               string
	GitHubAppID               int64
	GitHubInstallationID      int64
	GitHubAppPrivateKeyPath   string
	GitHubWebhookSecret       string
	GitHubBotUsername         string
	GitHubRepos               []string

	LLMBaseURL    string
	LLMAPIKey     string
	LLMModel      string
	LLMFastModel  string
	LLMTimeout    time.Duration
	LLMMaxRetries int

	AgentMaxSteps             int
	AgentMaxTokens            int
	AgentSkillsDir            string
	AgentDefaultSkills        []string
	AgentEnableWrite          bool
	AgentAdversarialSecurity  bool
	AgentEnableProofOfBug     bool
	SandboxMode               string
	SandboxRuntime            string
	SandboxImage              string
	SandboxRequireImageDigest bool
	OpsTelemetryPath          string
	AllowLLMTelemetrySharing  bool
	AlertWebhookURL           string
	DataDir                   string
	Workers                   int
	ReconcileInterval         time.Duration
	UpdateCheckInterval       time.Duration // 0 disables the outbound release check
	LogLevel                  string
}

// Default returns a Config populated with default values.
func Default() Config {
	return Config{
		ListenAddr:                ":8080",
		ForgeProvider:             "gitea",
		GiteaBotUsername:          "codespider",
		GitHubBaseURL:             "https://api.github.com",
		GitHubBotUsername:         "codespider",
		AllowUnsignedWebhooks:     false,
		AllowSameOwnerCrossRepo:   false,
		SkipDraftPRs:              true,
		IgnoreBotPRs:              true,
		StickySummary:             true,
		RequireCollaboratorForFix: true,
		LLMBaseURL:                "https://api.openai.com/v1",
		LLMModel:                  "gpt-5",
		LLMTimeout:                120 * time.Second,
		LLMMaxRetries:             2,
		AgentMaxSteps:             12,
		AgentMaxTokens:            32000,
		AgentSkillsDir:            "./skills",
		AgentDefaultSkills:        []string{"security", "code-quality", "testing"},
		AgentEnableWrite:          false,
		AgentAdversarialSecurity:  true,
		AgentEnableProofOfBug:     false,
		SandboxMode:               "disabled",
		SandboxRuntime:            "docker",
		SandboxImage:              "golang:1.26-trixie",
		DataDir:                   "./data",
		Workers:                   2,
		ReconcileInterval:         300 * time.Second,
		LogLevel:                  "info",
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
	cfg.GitHubBaseURL = strings.TrimRight(cfg.GitHubBaseURL, "/")
	cfg.ForgeProvider = strings.ToLower(strings.TrimSpace(cfg.ForgeProvider))
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
	switch c.ForgeProvider {
	case "gitea":
		if c.GiteaBaseURL == "" {
			errs = append(errs, errors.New("gitea.base_url is required"))
		}
		if c.GiteaToken == "" {
			errs = append(errs, errors.New("gitea.token is required"))
		}
	case "github":
		appConfigured := c.GitHubAppID != 0 || c.GitHubInstallationID != 0 || c.GitHubAppPrivateKeyPath != ""
		if appConfigured && (c.GitHubAppID <= 0 || c.GitHubInstallationID <= 0 || c.GitHubAppPrivateKeyPath == "") {
			errs = append(errs, errors.New("github.app_id, github.installation_id, and github.app_private_key_path must all be set together"))
		}
		if appConfigured && c.GitHubToken != "" {
			errs = append(errs, errors.New("configure either github.token or GitHub App credentials, not both"))
		}
		if !appConfigured && c.GitHubToken == "" {
			errs = append(errs, errors.New("github.token is required when forge.provider is github"))
		}
		if c.GitHubWebhookSecret == "" {
			errs = append(errs, errors.New("github.webhook_secret is required when forge.provider is github"))
		}
		u, err := url.Parse(c.GitHubBaseURL)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			errs = append(errs, errors.New("github.api_url must be an HTTPS URL without user info, query, or fragment"))
		}
	default:
		errs = append(errs, fmt.Errorf("forge.provider must be gitea or github, got %q", c.ForgeProvider))
	}
	if c.LLMBaseURL == "" {
		errs = append(errs, errors.New("llm.base_url is required"))
	}
	if c.LLMModel == "" {
		errs = append(errs, errors.New("llm.model is required"))
	}
	if c.LLMMaxRetries < 0 {
		errs = append(errs, fmt.Errorf("llm.max_retries must be >= 0, got %d", c.LLMMaxRetries))
	}
	if c.Workers < 1 {
		errs = append(errs, fmt.Errorf("daemon.workers must be >= 1, got %d", c.Workers))
	}
	if c.AgentMaxSteps < 1 {
		errs = append(errs, fmt.Errorf("agent.max_steps must be >= 1, got %d", c.AgentMaxSteps))
	}
	if c.UpdateCheckInterval < 0 {
		errs = append(errs, fmt.Errorf("daemon.update_check_hours must be >= 0, got %s", c.UpdateCheckInterval))
	}
	return errors.Join(errs...)
}

func parseYAML(content string, cfg *Config) error {
	lines := strings.Split(content, "\n")
	section := ""
	inListKey := ""
	defaultSkillsCleared := false
	giteaReposCleared := false
	githubReposCleared := false
	crossRepoCleared := false

	for lineNo, rawLine := range lines {
		cleaned := stripComment(rawLine)
		trimmed := strings.TrimSpace(cleaned)
		if trimmed == "" || trimmed == "---" {
			continue
		}

		indent := countLeadingSpaces(cleaned)

		// List item under current section/key (e.g. "    - security")
		if strings.HasPrefix(trimmed, "- ") {
			switch inListKey {
			case "agent.default_skills":
				if !defaultSkillsCleared {
					cfg.AgentDefaultSkills = nil
					defaultSkillsCleared = true
				}
				item := unquoteAndExpand(strings.TrimSpace(strings.TrimPrefix(trimmed, "- ")))
				if item != "" {
					cfg.AgentDefaultSkills = append(cfg.AgentDefaultSkills, item)
				}
				continue
			case "gitea.repos":
				if !giteaReposCleared {
					cfg.GiteaRepos = nil
					giteaReposCleared = true
				}
				item := unquoteAndExpand(strings.TrimSpace(strings.TrimPrefix(trimmed, "- ")))
				if item != "" {
					cfg.GiteaRepos = append(cfg.GiteaRepos, item)
				}
				continue
			case "github.repos":
				if !githubReposCleared {
					cfg.GitHubRepos = nil
					githubReposCleared = true
				}
				item := unquoteAndExpand(strings.TrimSpace(strings.TrimPrefix(trimmed, "- ")))
				if item != "" {
					cfg.GitHubRepos = append(cfg.GitHubRepos, item)
				}
				continue
			case "forge.repos":
				item := unquoteAndExpand(strings.TrimSpace(strings.TrimPrefix(trimmed, "- ")))
				if item != "" {
					cfg.ForgeRepos = append(cfg.ForgeRepos, item)
				}
				continue
			case "gitea.cross_repo_allowlist":
				if !crossRepoCleared {
					cfg.CrossRepoAllowlist = nil
					crossRepoCleared = true
				}
				item := unquoteAndExpand(strings.TrimSpace(strings.TrimPrefix(trimmed, "- ")))
				if item != "" {
					cfg.CrossRepoAllowlist = append(cfg.CrossRepoAllowlist, item)
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
			switch fullKey {
			case "agent.default_skills":
				inListKey = fullKey
				if !defaultSkillsCleared {
					cfg.AgentDefaultSkills = nil
					defaultSkillsCleared = true
				}
			case "gitea.repos":
				inListKey = fullKey
				if !giteaReposCleared {
					cfg.GiteaRepos = nil
					giteaReposCleared = true
				}
			case "github.repos":
				inListKey = fullKey
				if !githubReposCleared {
					cfg.GitHubRepos = nil
					githubReposCleared = true
				}
			case "forge.repos":
				inListKey = fullKey
				cfg.ForgeRepos = nil
			case "gitea.cross_repo_allowlist":
				inListKey = fullKey
				if !crossRepoCleared {
					cfg.CrossRepoAllowlist = nil
					crossRepoCleared = true
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
	case "forge.provider":
		cfg.ForgeProvider = val
	case "forge.repos":
		cfg.ForgeRepos = parseInlineList(rawVal)
	case "forge.skip_draft_prs":
		b, err := strconv.ParseBool(val)
		if err != nil {
			return err
		}
		cfg.SkipDraftPRs = b
	case "forge.ignore_bot_prs":
		b, err := strconv.ParseBool(val)
		if err != nil {
			return err
		}
		cfg.IgnoreBotPRs = b
	case "forge.sticky_summary":
		b, err := strconv.ParseBool(val)
		if err != nil {
			return err
		}
		cfg.StickySummary = b
	case "forge.require_collaborator_for_fix":
		b, err := strconv.ParseBool(val)
		if err != nil {
			return err
		}
		cfg.RequireCollaboratorForFix = b
	case "server.listen_addr", "listen_addr":
		cfg.ListenAddr = val
	case "server.admin_token", "admin_token":
		cfg.AdminToken = val
	case "gitea.base_url":
		cfg.GiteaBaseURL = val
	case "gitea.token":
		cfg.GiteaToken = val
	case "gitea.webhook_secret":
		cfg.GiteaWebhookSecret = val
	case "gitea.bot_username":
		cfg.GiteaBotUsername = val
	case "gitea.repos":
		cfg.GiteaRepos = parseInlineList(rawVal)
	case "gitea.allow_unsigned_webhooks":
		b, err := strconv.ParseBool(val)
		if err != nil {
			return err
		}
		cfg.AllowUnsignedWebhooks = b
	case "gitea.allow_same_owner_cross_repo":
		b, err := strconv.ParseBool(val)
		if err != nil {
			return err
		}
		cfg.AllowSameOwnerCrossRepo = b
	case "gitea.cross_repo_allowlist":
		cfg.CrossRepoAllowlist = parseInlineList(rawVal)
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
	case "gitea.sticky_summary":
		b, err := strconv.ParseBool(val)
		if err != nil {
			return err
		}
		cfg.StickySummary = b
	case "gitea.require_collaborator_for_fix":
		b, err := strconv.ParseBool(val)
		if err != nil {
			return err
		}
		cfg.RequireCollaboratorForFix = b
	case "github.api_url", "github.base_url":
		cfg.GitHubBaseURL = val
	case "github.token":
		cfg.GitHubToken = val
	case "github.app_id":
		n, err := strconv.ParseInt(val, 10, 64)
		if err != nil {
			return err
		}
		cfg.GitHubAppID = n
	case "github.installation_id":
		n, err := strconv.ParseInt(val, 10, 64)
		if err != nil {
			return err
		}
		cfg.GitHubInstallationID = n
	case "github.app_private_key_path":
		cfg.GitHubAppPrivateKeyPath = val
	case "github.webhook_secret":
		cfg.GitHubWebhookSecret = val
	case "github.bot_username":
		cfg.GitHubBotUsername = val
	case "github.repos":
		cfg.GitHubRepos = parseInlineList(rawVal)
	case "llm.base_url":
		cfg.LLMBaseURL = val
	case "llm.api_key":
		cfg.LLMAPIKey = val
	case "llm.model":
		cfg.LLMModel = val
	case "llm.fast_model":
		cfg.LLMFastModel = val
	case "llm.timeout_seconds":
		n, err := strconv.Atoi(val)
		if err != nil {
			return err
		}
		cfg.LLMTimeout = time.Duration(n) * time.Second
	case "llm.max_retries":
		n, err := strconv.Atoi(val)
		if err != nil {
			return err
		}
		cfg.LLMMaxRetries = n
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
	case "agent.adversarial_security":
		b, err := strconv.ParseBool(val)
		if err != nil {
			return err
		}
		cfg.AgentAdversarialSecurity = b
	case "agent.enable_proof_of_bug":
		b, err := strconv.ParseBool(val)
		if err != nil {
			return err
		}
		cfg.AgentEnableProofOfBug = b
	case "sandbox.mode":
		cfg.SandboxMode = strings.ToLower(val)
	case "sandbox.runtime":
		cfg.SandboxRuntime = strings.ToLower(val)
	case "sandbox.image":
		cfg.SandboxImage = val
	case "sandbox.require_image_digest":
		b, err := strconv.ParseBool(val)
		if err != nil {
			return err
		}
		cfg.SandboxRequireImageDigest = b
	case "ops.telemetry_file":
		cfg.OpsTelemetryPath = val
	case "ops.allow_llm_telemetry_sharing":
		b, err := strconv.ParseBool(val)
		if err != nil {
			return err
		}
		cfg.AllowLLMTelemetrySharing = b
	case "alert.webhook_url":
		cfg.AlertWebhookURL = val
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
	case "daemon.update_check_hours":
		n, err := strconv.Atoi(val)
		if err != nil {
			return err
		}
		if n < 0 || n > 24*365 {
			return fmt.Errorf("daemon.update_check_hours must be between 0 and %d", 24*365)
		}
		cfg.UpdateCheckInterval = time.Duration(n) * time.Hour
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
