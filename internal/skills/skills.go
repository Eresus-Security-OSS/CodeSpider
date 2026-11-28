// Package skills loads markdown-based agent skills (e.g., security, code-quality)
// with frontmatter metadata, path-based auto-activation, and prompt formatting.
package skills

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/Eresus-Security-OSS/CodeSpider/internal/workspace"
)

var validSkillNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

// Skill represents a loaded SKILL.md instruction module.
type Skill struct {
	Name        string   `json:"name"`
	Version     string   `json:"version,omitempty"`
	Description string   `json:"description"`
	Tags        []string `json:"tags,omitempty"`
	Paths       []string `json:"paths,omitempty"`
	Tools       []string `json:"tools,omitempty"`
	Body        string   `json:"-"`
	Path        string   `json:"path"`
}

// LoadSelected loads the named skills from dir/<name>/SKILL.md.
// Missing skills are returned as an error so misconfiguration is caught early.
func LoadSelected(dir string, names []string) ([]Skill, error) {
	if len(names) == 0 || dir == "" {
		return nil, nil
	}
	out := make([]Skill, 0, len(names))
	seen := make(map[string]bool, len(names))
	for _, name := range names {
		name = strings.TrimSpace(name)
		if name == "" || seen[name] {
			continue
		}
		if !validSkillNameRe.MatchString(name) {
			return nil, fmt.Errorf("invalid skill name %q", name)
		}
		rel := filepath.Join(name, "SKILL.md")
		p, err := workspace.ResolveSafePath(dir, rel)
		if err != nil {
			return nil, fmt.Errorf("load skill %q: %w", name, err)
		}
		raw, err := workspace.ReadSafeFile(dir, rel, 256*1024)
		if err != nil {
			return nil, fmt.Errorf("load skill %q: %w", name, err)
		}
		seen[name] = true
		out = append(out, parseSkill(name, p, string(raw)))
	}
	return out, nil
}

// DiscoverAll scans dir for valid <name>/SKILL.md modules and returns them sorted by name.
func DiscoverAll(dir string) ([]Skill, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var names []string
	for _, entry := range entries {
		if !entry.IsDir() || !validSkillNameRe.MatchString(entry.Name()) {
			continue
		}
		skillFile := filepath.Join(dir, entry.Name(), "SKILL.md")
		if info, statErr := os.Stat(skillFile); statErr == nil && !info.IsDir() {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)
	return LoadSelected(dir, names)
}

// SelectForPaths loads selectedNames plus any discovered skills whose Paths match changedPaths.
func SelectForPaths(dir string, selectedNames, changedPaths []string) ([]Skill, error) {
	loaded, err := LoadSelected(dir, selectedNames)
	if err != nil {
		return nil, err
	}
	if len(changedPaths) == 0 || strings.TrimSpace(dir) == "" {
		return loaded, nil
	}
	all, discErr := DiscoverAll(dir)
	if discErr != nil {
		return loaded, nil
	}
	seen := make(map[string]bool, len(loaded))
	for _, sk := range loaded {
		seen[sk.Name] = true
	}
	for _, sk := range all {
		if seen[sk.Name] || len(sk.Paths) == 0 {
			continue
		}
		if matchesAnySkillPath(sk.Paths, changedPaths) {
			seen[sk.Name] = true
			loaded = append(loaded, sk)
		}
	}
	return loaded, nil
}

func matchesAnySkillPath(patterns, changedPaths []string) bool {
	for _, cp := range changedPaths {
		slash := strings.ToLower(filepath.ToSlash(cp))
		base := strings.ToLower(filepath.Base(slash))
		for _, pat := range patterns {
			p := strings.ToLower(strings.TrimSpace(pat))
			if p == "" {
				continue
			}
			if ok, _ := filepath.Match(p, base); ok {
				return true
			}
			if ok, _ := filepath.Match(p, slash); ok {
				return true
			}
			clean := strings.Trim(p, "*")
			if clean != "" && strings.Contains(slash, clean) {
				return true
			}
		}
	}
	return false
}

// FormatPrompt renders loaded skills into a compact system-prompt section.
func FormatPrompt(loaded []Skill) string {
	if len(loaded) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("## Active Review Skills\n")
	for _, s := range loaded {
		b.WriteString(fmt.Sprintf("\n### Skill: %s", s.Name))
		if s.Version != "" {
			b.WriteString(" (v" + s.Version + ")")
		}
		b.WriteByte('\n')
		if s.Description != "" {
			b.WriteString(fmt.Sprintf("Focus: %s\n", s.Description))
		}
		if len(s.Tools) > 0 {
			b.WriteString("Recommended tools: " + strings.Join(s.Tools, ", ") + "\n")
		}
		b.WriteByte('\n')
		b.WriteString(strings.TrimSpace(s.Body))
		b.WriteString("\n")
	}
	return b.String()
}

func parseSkill(fallbackName, path, content string) Skill {
	sk := Skill{
		Name: fallbackName,
		Path: path,
		Body: content,
	}
	trimmed := strings.TrimSpace(content)
	if !strings.HasPrefix(trimmed, "---") {
		return sk
	}
	rest := strings.TrimPrefix(trimmed, "---")
	endIdx := strings.Index(rest, "\n---")
	if endIdx == -1 {
		return sk
	}
	frontmatter := rest[:endIdx]
	sk.Body = strings.TrimSpace(rest[endIdx+4:])
	for _, line := range strings.Split(frontmatter, "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key := strings.TrimSpace(strings.ToLower(k))
		rawVal := strings.TrimSpace(v)
		val := strings.Trim(rawVal, `"'`)
		switch key {
		case "name":
			if val != "" {
				sk.Name = val
			}
		case "version":
			sk.Version = val
		case "description":
			sk.Description = val
		case "tags":
			sk.Tags = parseInlineList(rawVal)
		case "paths":
			sk.Paths = parseInlineList(rawVal)
		case "tools":
			sk.Tools = parseInlineList(rawVal)
		}
	}
	return sk
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
		item := strings.Trim(strings.TrimSpace(p), `"'`)
		if item != "" {
			out = append(out, item)
		}
	}
	return out
}
