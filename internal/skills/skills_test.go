package skills

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadSelectedBuiltinSkills(t *testing.T) {
	skillsDir := filepath.Join("..", "..", "skills")
	loaded, err := LoadSelected(skillsDir, []string{"security", "code-quality"})
	if err != nil {
		t.Fatalf("LoadSelected failed: %v", err)
	}
	if len(loaded) != 2 {
		t.Fatalf("expected 2 skills, got %d", len(loaded))
	}
	prompt := FormatPrompt(loaded)
	if !strings.Contains(prompt, "Skill: security") || !strings.Contains(prompt, "Skill: code-quality") {
		t.Fatalf("formatted prompt missing expected skills:\n%s", prompt)
	}
}
