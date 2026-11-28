// Package repoconfig loads repository-native review instructions and .codespider.yaml settings.
package repoconfig

import (
	"path/filepath"
	"strings"

	"github.com/Eresus-Security-OSS/CodeSpider/internal/workspace"
)

const (
	maxInstructionBytes = 16 * 1024
	maxRepoConfigBytes  = 256 * 1024
)

var instructionFiles = []string{
	"AGENTS.md",
	".gitea/review-instructions.md",
	".codespider/instructions.md",
}

// Config holds per-repository review settings loaded from the PR worktree.
type Config struct {
	Enabled             bool
	IgnorePaths         []string
	Skills              []string
	MinSeverity         string
	Model               string
	AutoLabel           bool
	AutoAssignReviewers bool
	AdversarialSecurity *bool
	ForbidImports       map[string][]string
	Instructions        string
}

// Load reads .codespider.yaml/.yml and repository instruction files from worktreeDir.
func Load(worktreeDir string) Config {
	return LoadWithTrustedBase(worktreeDir, nil)
}

// LoadWithTrustedBase loads repository instructions from worktreeDir while enforcing
// security/gate settings (enabled, ignore_paths, min_severity, adversarial_security, forbid_imports)
// from trustedBaseYAML when provided (so untrusted PR heads cannot disable review gates).
func LoadWithTrustedBase(worktreeDir string, trustedBaseYAML []byte) Config {
	cfg := Config{Enabled: true, ForbidImports: make(map[string][]string)}
	if worktreeDir != "" {
		for _, name := range []string{".codespider.yaml", ".codespider.yml"} {
			if raw, err := workspace.ReadSafeFile(worktreeDir, name, maxRepoConfigBytes); err == nil {
				parseYAMLSubset(string(raw), &cfg)
				break
			}
		}
	}

	if len(trustedBaseYAML) > 0 {
		baseCfg := Config{Enabled: true, ForbidImports: make(map[string][]string)}
		parseYAMLSubset(string(trustedBaseYAML), &baseCfg)
		cfg.Enabled = baseCfg.Enabled
		cfg.IgnorePaths = baseCfg.IgnorePaths
		cfg.MinSeverity = baseCfg.MinSeverity
		cfg.AdversarialSecurity = baseCfg.AdversarialSecurity
		cfg.ForbidImports = baseCfg.ForbidImports
		cfg.Model = baseCfg.Model
		cfg.Skills = baseCfg.Skills
		cfg.AutoLabel = baseCfg.AutoLabel
		cfg.AutoAssignReviewers = baseCfg.AutoAssignReviewers
	}

	if worktreeDir == "" {
		return cfg
	}

	var sections []string
	for _, rel := range instructionFiles {
		raw, err := workspace.ReadSafeFile(worktreeDir, rel, maxInstructionBytes+1)
		if err != nil {
			continue
		}
		text := strings.TrimSpace(string(raw))
		if text == "" {
			continue
		}
		if len(text) > maxInstructionBytes {
			text = text[:maxInstructionBytes] + "\n... (truncated)"
		}
		sections = append(sections, "### From "+rel+"\n"+text)
	}
	if cfg.Instructions != "" {
		sections = append(sections, "### From .codespider.yaml\n"+strings.TrimSpace(cfg.Instructions))
	}
	cfg.Instructions = strings.Join(sections, "\n\n")
	return cfg
}

// FilterDiff removes file sections from a unified diff whose paths match ignorePatterns.
func FilterDiff(diff string, ignorePatterns []string) (filtered string, skipped []string) {
	if diff == "" || len(ignorePatterns) == 0 {
		return diff, nil
	}

	chunks := splitDiffChunks(diff)
	var kept []string
	for _, chunk := range chunks {
		path := extractDiffPath(chunk)
		if path != "" && matchesAny(path, ignorePatterns) {
			skipped = append(skipped, path)
			continue
		}
		kept = append(kept, chunk)
	}
	return strings.Join(kept, ""), skipped
}

func splitDiffChunks(diff string) []string {
	const marker = "diff --git "
	var chunks []string
	idx := strings.Index(diff, marker)
	if idx == -1 {
		return []string{diff}
	}
	if idx > 0 {
		chunks = append(chunks, diff[:idx])
	}
	rest := diff[idx:]
	for {
		next := strings.Index(rest[len(marker):], "\n"+marker)
		if next == -1 {
			chunks = append(chunks, rest)
			break
		}
		splitAt := len(marker) + next + 1
		chunks = append(chunks, rest[:splitAt])
		rest = rest[splitAt:]
	}
	return chunks
}

func extractDiffPath(chunk string) string {
	firstLine, _, _ := strings.Cut(chunk, "\n")
	if !strings.HasPrefix(firstLine, "diff --git ") {
		return ""
	}
	rest := strings.TrimPrefix(firstLine, "diff --git ")
	// Format: a/<old> b/<new>
	if idx := strings.LastIndex(rest, " b/"); idx != -1 {
		return strings.TrimSpace(rest[idx+3:])
	}
	return ""
}

func matchesAny(path string, patterns []string) bool {
	slashPath := filepath.ToSlash(path)
	base := filepath.Base(slashPath)
	for _, p := range patterns {
		pat := strings.TrimSpace(filepath.ToSlash(p))
		if pat == "" {
			continue
		}
		if strings.HasSuffix(pat, "/**") {
			prefix := strings.TrimSuffix(pat, "**")
			if strings.HasPrefix(slashPath, prefix) {
				return true
			}
		}
		if strings.HasSuffix(pat, "/") && strings.HasPrefix(slashPath, pat) {
			return true
		}
		if strings.HasPrefix(pat, "**/") {
			sub := strings.TrimPrefix(pat, "**/")
			if ok, _ := filepath.Match(sub, base); ok {
				return true
			}
			if ok, _ := filepath.Match(sub, slashPath); ok {
				return true
			}
		}
		if ok, _ := filepath.Match(pat, slashPath); ok {
			return true
		}
		if !strings.Contains(pat, "/") {
			if ok, _ := filepath.Match(pat, base); ok {
				return true
			}
		}
	}
	return false
}

// parseYAMLSubset parses a minimal subset of .codespider.yaml without external dependencies.
func parseYAMLSubset(content string, cfg *Config) {
	lines := strings.Split(content, "\n")
	inListKey := ""
	inBlockInstr := false
	var blockLines []string

	for _, rawLine := range lines {
		trimmed := strings.TrimSpace(rawLine)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			if inBlockInstr {
				blockLines = append(blockLines, "")
			}
			continue
		}

		if inBlockInstr {
			if strings.HasPrefix(rawLine, " ") || strings.HasPrefix(rawLine, "\t") {
				blockLines = append(blockLines, trimmed)
				continue
			}
			cfg.Instructions = strings.Join(blockLines, "\n")
			inBlockInstr = false
			blockLines = nil
		}

		if strings.HasPrefix(trimmed, "- ") && inListKey != "" {
			item := strings.Trim(strings.TrimSpace(strings.TrimPrefix(trimmed, "- ")), `"'`)
			if item != "" {
				switch inListKey {
				case "ignore_paths":
					cfg.IgnorePaths = append(cfg.IgnorePaths, item)
				case "skills":
					cfg.Skills = append(cfg.Skills, item)
				}
			}
			continue
		}

		key, val, ok := strings.Cut(trimmed, ":")
		if !ok {
			continue
		}
		inListKey = ""
		key = strings.ToLower(strings.TrimSpace(key))
		val = strings.TrimSpace(val)

		switch key {
		case "enabled":
			if strings.EqualFold(val, "false") {
				cfg.Enabled = false
			} else if strings.EqualFold(val, "true") {
				cfg.Enabled = true
			}
		case "ignore_paths":
			if val == "" {
				inListKey = "ignore_paths"
			} else {
				// Inline list: [vendor/**, *.lock]
				val = strings.Trim(val, "[]")
				for _, part := range strings.Split(val, ",") {
					item := strings.Trim(strings.TrimSpace(part), `"'`)
					if item != "" {
						cfg.IgnorePaths = append(cfg.IgnorePaths, item)
					}
				}
			}
		case "skills":
			if val == "" {
				inListKey = "skills"
			} else {
				val = strings.Trim(val, "[]")
				for _, part := range strings.Split(val, ",") {
					item := strings.Trim(strings.TrimSpace(part), `"'`)
					if item != "" {
						cfg.Skills = append(cfg.Skills, item)
					}
				}
			}
		case "min_severity", "severity_threshold":
			sev := strings.ToLower(strings.Trim(val, `"'`))
			if sev == "info" || sev == "warning" || sev == "critical" {
				cfg.MinSeverity = sev
			}
		case "model":
			cfg.Model = strings.Trim(val, `"'`)
		case "auto_label":
			cfg.AutoLabel = strings.EqualFold(val, "true")
		case "auto_assign_reviewers":
			cfg.AutoAssignReviewers = strings.EqualFold(val, "true")
		case "adversarial_security":
			if strings.EqualFold(val, "true") {
				b := true
				cfg.AdversarialSecurity = &b
			} else if strings.EqualFold(val, "false") {
				b := false
				cfg.AdversarialSecurity = &b
			}
		case "forbid_imports":
			// Format: "internal/domain -> net/http, os/exec" or inline
			if val != "" {
				for _, rule := range strings.Split(strings.Trim(val, "[]"), ";") {
					pkgPat, badList, okRule := strings.Cut(rule, "->")
					if !okRule {
						continue
					}
					pkgPat = strings.TrimSpace(strings.Trim(pkgPat, `"'`))
					if cfg.ForbidImports == nil {
						cfg.ForbidImports = make(map[string][]string)
					}
					for _, bad := range strings.Split(badList, ",") {
						b := strings.TrimSpace(strings.Trim(bad, `"'`))
						if b != "" {
							cfg.ForbidImports[pkgPat] = append(cfg.ForbidImports[pkgPat], b)
						}
					}
				}
			}
		case "instructions":
			if val == "|" || val == ">" {
				inBlockInstr = true
			} else if val != "" {
				cfg.Instructions = strings.Trim(val, `"'`)
			}
		}
	}
	if inBlockInstr && len(blockLines) > 0 {
		cfg.Instructions = strings.Join(blockLines, "\n")
	}
}

// ExtractChangedPaths returns deduplicated file paths touched by a unified diff.
func ExtractChangedPaths(diff string) []string {
	if diff == "" {
		return nil
	}
	seen := make(map[string]struct{})
	var paths []string
	for _, chunk := range splitDiffChunks(diff) {
		p := extractDiffPath(chunk)
		if p != "" {
			if _, ok := seen[p]; !ok {
				seen[p] = struct{}{}
				paths = append(paths, p)
			}
		}
	}
	return paths
}
