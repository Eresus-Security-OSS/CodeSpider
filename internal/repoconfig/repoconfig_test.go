package repoconfig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadRepoConfigAndInstructions(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "AGENTS.md"), []byte("Always check SQL queries for parameterization."), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, ".gitea"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".gitea", "review-instructions.md"), []byte("Prefer early returns."), 0o644); err != nil {
		t.Fatal(err)
	}
	yamlCfg := `
review:
  enabled: true
  min_severity: warning
  skills:
    - security
    - performance
  ignore_paths:
    - "*.lock"
    - "vendor/**"
  instructions: |
    Verify context propagation on all DB calls.
`
	if err := os.WriteFile(filepath.Join(dir, ".codespider.yaml"), []byte(yamlCfg), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg := Load(dir)
	if !cfg.Enabled {
		t.Fatal("expected Enabled=true")
	}
	if cfg.MinSeverity != "warning" {
		t.Fatalf("expected MinSeverity=warning, got %q", cfg.MinSeverity)
	}
	if len(cfg.Skills) != 2 || cfg.Skills[0] != "security" || cfg.Skills[1] != "performance" {
		t.Fatalf("unexpected skills: %#v", cfg.Skills)
	}
	if len(cfg.IgnorePaths) != 2 || cfg.IgnorePaths[0] != "*.lock" || cfg.IgnorePaths[1] != "vendor/**" {
		t.Fatalf("unexpected ignore paths: %#v", cfg.IgnorePaths)
	}
	if !strings.Contains(cfg.Instructions, "AGENTS.md") ||
		!strings.Contains(cfg.Instructions, "Prefer early returns") ||
		!strings.Contains(cfg.Instructions, "Verify context propagation") {
		t.Fatalf("missing expected instructions:\n%s", cfg.Instructions)
	}
}

func TestFilterDiff(t *testing.T) {
	diff := strings.Join([]string{
		"diff --git a/go.sum b/go.sum",
		"index 111..222 100644",
		"+foo v1.0.0",
		"diff --git a/vendor/lib/a.go b/vendor/lib/a.go",
		"+package lib",
		"diff --git a/internal/app.go b/internal/app.go",
		"+func Run() {}",
	}, "\n") + "\n"

	filtered, skipped := FilterDiff(diff, []string{"go.sum", "vendor/**"})
	if len(skipped) != 2 {
		t.Fatalf("expected 2 skipped files, got %v", skipped)
	}
	if strings.Contains(filtered, "go.sum") || strings.Contains(filtered, "vendor/lib/a.go") {
		t.Fatalf("ignored files still present in filtered diff:\n%s", filtered)
	}
	if !strings.Contains(filtered, "internal/app.go") {
		t.Fatalf("expected internal/app.go to remain in diff:\n%s", filtered)
	}
}

func TestCodeOwnersAndExtendedRepoConfig(t *testing.T) {
	dir := t.TempDir()
	co := `
# Global fallback
* @alice
/internal/security/ @bob @alice
*.go @carol
`
	if err := os.MkdirAll(filepath.Join(dir, ".gitea"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".gitea", "CODEOWNERS"), []byte(co), 0o644); err != nil {
		t.Fatal(err)
	}
	yamlCfg := `
review:
  enabled: true
  model: gpt-5-mini
  auto_label: true
  auto_assign_reviewers: true
  adversarial_security: false
`
	if err := os.WriteFile(filepath.Join(dir, ".codespider.yaml"), []byte(yamlCfg), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg := Load(dir)
	if cfg.Model != "gpt-5-mini" || !cfg.AutoLabel || !cfg.AutoAssignReviewers {
		t.Fatalf("unexpected extended repoconfig: %+v", cfg)
	}
	if cfg.AdversarialSecurity == nil || *cfg.AdversarialSecurity {
		t.Fatalf("expected AdversarialSecurity=false, got %v", cfg.AdversarialSecurity)
	}

	rules := LoadCodeOwners(dir)
	reviewers := MatchCodeOwners(rules, []string{"internal/security/auth.go", "README.md"}, "alice")
	// internal/security/auth.go matches *.go last (@carol), README.md matches * (@alice, excluded)
	if len(reviewers) != 1 || reviewers[0] != "carol" {
		t.Fatalf("unexpected matched reviewers: %#v", reviewers)
	}
}
