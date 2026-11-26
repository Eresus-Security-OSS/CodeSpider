package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAuditLoggerWritesJSONL(t *testing.T) {
	dir := t.TempDir()
	l := NewLogger(dir)
	l.Log(Event{
		Actor:    "alice",
		PRKey:    "acme/api#1",
		Action:   "tool:search_org_repos",
		Decision: "deny",
		Reason:   "fork PR",
	})

	raw, err := os.ReadFile(filepath.Join(dir, "audit.jsonl"))
	if err != nil {
		t.Fatalf("read audit.jsonl failed: %v", err)
	}
	if !strings.Contains(string(raw), `"decision":"deny"`) {
		t.Fatalf("unexpected audit log contents: %s", string(raw))
	}
}
