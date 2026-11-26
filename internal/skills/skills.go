// Package skills loads markdown-based agent skills (e.g., security, code-quality).
package skills

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Skill represents a loaded SKILL.md instruction module.
type Skill struct {
	Name        string
	Description string
	Body        string
	Path        string
}

// LoadSelected loads the named skills from dir/<name>/SKILL.md.
// Missing skills are returned as an error so misconfiguration is caught early.
func LoadSelected(dir string, names []string) ([]Skill, error) {
	if len(names) == 0 || dir == "" {
		return nil, nil
	}
	out := make([]Skill, 0, len(names))
	for _, name := range names {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		p := filepath.Join(dir, name, "SKILL.md")
		raw, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("load skill %q: %w", name, err)
		}
		sk := parseSkill(name, p, string(raw))
		out = append(out, sk)
	}
	return out, nil
}

// FormatPrompt renders loaded skills into a compact system-prompt section.
func FormatPrompt(loaded []Skill) string {
	if len(loaded) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("## Active Review Skills\n")
	for _, s := range loaded {
		b.WriteString(fmt.Sprintf("\n### Skill: %s\n", s.Name))
		if s.Description != "" {
			b.WriteString(fmt.Sprintf("Focus: %s\n\n", s.Description))
		}
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
		val := strings.Trim(strings.TrimSpace(v), `"'`)
		switch key {
		case "name":
			if val != "" {
				sk.Name = val
			}
		case "description":
			sk.Description = val
		}
	}
	return sk
}
