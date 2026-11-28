package repoconfig

import (
	"strings"
	"testing"
)

func TestPathInstructionsParseAndMatch(t *testing.T) {
	var cfg Config
	parseYAMLSubset(`review:
  path_instructions:
    - "internal/db/**: Check every tx has a deferred Rollback."
    - "*.sql: Flag destructive DDL without a rollback script."
    - "no-colon-item"
    - "empty/**: "
  instructions: general note
`, &cfg)

	if len(cfg.PathInstructions) != 2 {
		t.Fatalf("expected 2 valid path instructions, got %+v", cfg.PathInstructions)
	}
	if cfg.Instructions != "general note" {
		t.Fatalf("list parsing must not leak into later keys, got %q", cfg.Instructions)
	}

	got := cfg.InstructionsForPaths([]string{"internal/db/store.go", "internal/db/tx.go", "README.md"})
	if !strings.Contains(got, "deferred Rollback") || strings.Contains(got, "destructive DDL") {
		t.Fatalf("expected only the db instruction, got %q", got)
	}
	if !strings.Contains(got, "internal/db/store.go, internal/db/tx.go") {
		t.Fatalf("expected matched paths to be listed, got %q", got)
	}

	if cfg.InstructionsForPaths([]string{"main.go"}) != "" {
		t.Fatal("expected no instructions when nothing matches")
	}
	if got := cfg.InstructionsForPaths([]string{"migrations/001.sql"}); !strings.Contains(got, "destructive DDL") {
		t.Fatalf("expected basename glob to match nested .sql, got %q", got)
	}
}
