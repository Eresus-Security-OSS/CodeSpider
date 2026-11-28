package repoconfig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGatingAndChecksParse(t *testing.T) {
	var cfg Config
	parseYAMLSubset(`review:
  base_branches:
    - main
    - "release/*"
  ignore_title_keywords: [WIP, "[skip review]"]
  title_pattern: "^(feat|fix)(\(.+\))?: .+"
  require_description: true
  max_changed_lines: 400
`, &cfg)

	if len(cfg.BaseBranches) != 2 || cfg.BaseBranches[1] != "release/*" {
		t.Fatalf("base_branches: %+v", cfg.BaseBranches)
	}
	if len(cfg.IgnoreTitleKeywords) != 2 || cfg.IgnoreTitleKeywords[1] != "[skip review]" {
		t.Fatalf("ignore_title_keywords: %+v", cfg.IgnoreTitleKeywords)
	}
	if cfg.TitlePattern != `^(feat|fix)(\(.+\))?: .+` || !cfg.RequireDescription || cfg.MaxChangedLines != 400 {
		t.Fatalf("checks config: %+v", cfg)
	}
}

func TestSkipReason(t *testing.T) {
	cfg := Config{BaseBranches: []string{"main", "release/*"}, IgnoreTitleKeywords: []string{"wip", "[skip review]"}}

	cases := []struct {
		base, title string
		skip        bool
	}{
		{"main", "feat: add x", false},
		{"release/1.2", "fix: y", false},
		{"release/1.2/hotfix", "fix: y", true}, // * does not cross "/"
		{"develop", "feat: z", true},
		{"main", "WIP: half done", true},
		{"main", "feat: x [SKIP REVIEW]", true},
		{"", "feat: base unknown", false},
	}
	for _, c := range cases {
		if got := cfg.SkipReason(c.base, c.title) != ""; got != c.skip {
			t.Errorf("SkipReason(%q, %q) skip=%v, want %v", c.base, c.title, got, c.skip)
		}
	}
	if (Config{}).SkipReason("anything", "WIP") != "" {
		t.Fatal("empty config must never skip")
	}
}

func TestEvaluatePreMergeChecks(t *testing.T) {
	cfg := Config{TitlePattern: `^(feat|fix): .+`, RequireDescription: true, MaxChangedLines: 100}

	good := cfg.EvaluatePreMergeChecks("feat: add thing", "why and how", 100)
	if len(good) != 3 {
		t.Fatalf("expected 3 results, got %+v", good)
	}
	for _, r := range good {
		if !r.Passed {
			t.Errorf("expected %q to pass: %+v", r.Name, r)
		}
	}

	bad := cfg.EvaluatePreMergeChecks("update stuff", "  \n", 101)
	for _, r := range bad {
		if r.Passed {
			t.Errorf("expected %q to fail: %+v", r.Name, r)
		}
	}

	invalid := Config{TitlePattern: "("}.EvaluatePreMergeChecks("x", "", 0)
	if len(invalid) != 1 || invalid[0].Passed || !strings.Contains(invalid[0].Detail, "not a valid") {
		t.Fatalf("invalid regex must be reported, got %+v", invalid)
	}
	if got := (Config{}).EvaluatePreMergeChecks("x", "", 5); got != nil {
		t.Fatalf("unconfigured checks must be omitted, got %+v", got)
	}
}

func TestTrustedBaseOwnsGatingSettings(t *testing.T) {
	dir := t.TempDir()
	head := "base_branches: [attacker]\nignore_title_keywords: [anything]\nmax_changed_lines: 999999\nrequire_description: false\n"
	if err := os.WriteFile(filepath.Join(dir, ".codespider.yaml"), []byte(head), 0o644); err != nil {
		t.Fatal(err)
	}
	trusted := []byte("base_branches: [main]\nmax_changed_lines: 50\nrequire_description: true\n")

	cfg := LoadWithTrustedBase(dir, trusted)
	if len(cfg.BaseBranches) != 1 || cfg.BaseBranches[0] != "main" {
		t.Fatalf("PR head must not override base_branches, got %+v", cfg.BaseBranches)
	}
	if len(cfg.IgnoreTitleKeywords) != 0 {
		t.Fatalf("PR head must not add ignore_title_keywords, got %+v", cfg.IgnoreTitleKeywords)
	}
	if cfg.MaxChangedLines != 50 || !cfg.RequireDescription {
		t.Fatalf("PR head must not weaken checks, got %+v", cfg)
	}
}
