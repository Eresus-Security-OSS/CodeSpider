package skills

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadSelectedAndDiscoverAllBuiltinSkills(t *testing.T) {
	skillsDir := filepath.Join("..", "..", "skills")
	all, err := DiscoverAll(skillsDir)
	if err != nil {
		t.Fatalf("DiscoverAll failed: %v", err)
	}
	if len(all) != 10 {
		t.Fatalf("expected 10 built-in skills, got %d", len(all))
	}

	loaded, err := LoadSelected(skillsDir, []string{
		"security", "code-quality", "testing", "performance", "concurrency",
		"chaos-resilience", "api-contracts", "migrations-db", "iac-supply-chain", "redteam-adversarial",
	})
	if err != nil {
		t.Fatalf("LoadSelected failed: %v", err)
	}
	if len(loaded) != 10 {
		t.Fatalf("expected 10 skills, got %d", len(loaded))
	}
	prompt := FormatPrompt(loaded)
	for _, expected := range []string{
		"Skill: security", "Skill: code-quality", "Skill: testing", "Skill: performance",
		"Skill: concurrency", "Skill: chaos-resilience", "Skill: api-contracts",
		"Skill: migrations-db", "Skill: iac-supply-chain", "Skill: redteam-adversarial",
		"Recommended tools:",
	} {
		if !strings.Contains(prompt, expected) {
			t.Fatalf("formatted prompt missing %q", expected)
		}
	}
}

func TestSelectForPathsAutoActivatesMatchingSkills(t *testing.T) {
	skillsDir := filepath.Join("..", "..", "skills")
	selected, err := SelectForPaths(skillsDir, []string{"security"}, []string{"db/migrations/001.up.sql", "Dockerfile"})
	if err != nil {
		t.Fatalf("SelectForPaths failed: %v", err)
	}
	names := make(map[string]bool)
	for _, sk := range selected {
		names[sk.Name] = true
	}
	if !names["security"] || !names["migrations-db"] || !names["iac-supply-chain"] {
		t.Fatalf("expected security + migrations-db + iac-supply-chain, got %v", names)
	}
}

func TestLoadSelectedRejectsTraversal(t *testing.T) {
	skillsDir := filepath.Join("..", "..", "skills")
	if _, err := LoadSelected(skillsDir, []string{"../cmd/codespider"}); err == nil {
		t.Fatal("expected path traversal skill name to be rejected")
	}
	if _, err := LoadSelected(skillsDir, []string{"security/../../etc"}); err == nil {
		t.Fatal("expected nested traversal skill name to be rejected")
	}
}
