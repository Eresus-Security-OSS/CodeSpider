package tools

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteToolsDisabledByDefault(t *testing.T) {
	reg := NewRegistry(Params{WorktreeDir: t.TempDir()})
	for _, def := range reg.Definitions() {
		if def.Function.Name == "write_file" || def.Function.Name == "edit_file" || def.Function.Name == "commit_and_push" {
			t.Fatalf("unexpected write tool %q when EnableWrite is false", def.Function.Name)
		}
	}
}

func TestWriteAndEditFileWithGuardrails(t *testing.T) {
	dir := t.TempDir()
	reg := NewRegistry(Params{
		WorktreeDir: dir,
		EnableWrite: true,
	})

	ctx := context.Background()

	// write_file creates nested file
	out, err := reg.Execute(ctx, "write_file", `{"path":"pkg/hello.go","content":"package pkg\n\nfunc Hi() string { return \"old\" }\n"}`)
	if err != nil {
		t.Fatalf("write_file failed: %v", err)
	}
	if !strings.Contains(out, "pkg/hello.go") {
		t.Fatalf("unexpected write_file output: %s", out)
	}

	// edit_file replaces unique substring
	if _, err := reg.Execute(ctx, "edit_file", `{"path":"pkg/hello.go","old_text":"\"old\"","new_text":"\"new\""}`); err != nil {
		t.Fatalf("edit_file failed: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "pkg", "hello.go"))
	if err != nil {
		t.Fatalf("read back failed: %v", err)
	}
	if !strings.Contains(string(got), `return "new"`) {
		t.Fatalf("expected updated content, got:\n%s", string(got))
	}

	// reject .git writes
	if _, err := reg.Execute(ctx, "write_file", `{"path":".git/config","content":"bad"}`); err == nil {
		t.Fatal("expected error writing to .git/config")
	}

	// reject path traversal outside worktree
	if _, err := reg.Execute(ctx, "write_file", `{"path":"../escape.txt","content":"bad"}`); err == nil {
		t.Fatal("expected error on path traversal")
	}
}
