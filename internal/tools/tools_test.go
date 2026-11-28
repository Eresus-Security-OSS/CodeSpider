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

func TestAddInlineCommentWithSuggestion(t *testing.T) {
	reg := NewRegistry(Params{WorktreeDir: t.TempDir()})
	out, err := reg.Execute(context.Background(), "add_inline_comment", `{
		"path": "main.go",
		"line": 12,
		"severity": "warning",
		"body": "Check returned error",
		"suggestion": "if err := run(); err != nil {\n\treturn err\n}"
	}`)
	if err != nil {
		t.Fatalf("add_inline_comment failed: %v", err)
	}
	if !strings.Contains(out, "main.go:12") {
		t.Fatalf("unexpected output: %s", out)
	}
	if len(reg.State.InlineComments) != 1 {
		t.Fatalf("expected 1 inline comment, got %d", len(reg.State.InlineComments))
	}
	body := reg.State.InlineComments[0].Body
	if !strings.Contains(body, "**[WARNING]** Check returned error") {
		t.Fatalf("missing severity/body in comment: %s", body)
	}
	if !strings.Contains(body, "```suggestion\nif err := run(); err != nil {\n\treturn err\n}\n```") {
		t.Fatalf("missing suggestion block in comment:\n%s", body)
	}
}

func TestAnnotateDiffMinSeverityAndListFiles(t *testing.T) {
	rawDiff := strings.Join([]string{
		"diff --git a/app.go b/app.go",
		"--- a/app.go",
		"+++ b/app.go",
		"@@ -10,3 +10,4 @@ package main",
		" func a() {",
		"-    old()",
		"+    new1()",
		"+    new2()",
		" }",
	}, "\n")

	annotated := AnnotateDiff(rawDiff)
	if !strings.Contains(annotated, "[L10]  func a() {") ||
		!strings.Contains(annotated, "[DEL] -    old()") ||
		!strings.Contains(annotated, "[L11] +    new1()") ||
		!strings.Contains(annotated, "[L12] +    new2()") {
		t.Fatalf("unexpected annotated diff:\n%s", annotated)
	}

	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "pkg"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "pkg", "one.go"), []byte("package pkg\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	reg := NewRegistry(Params{
		WorktreeDir:     dir,
		Diff:            rawDiff,
		IncrementalDiff: rawDiff,
		PreviousSHA:     "1111111",
		MinSeverity:     "warning",
	})

	ctx := context.Background()
	filesOut, err := reg.Execute(ctx, "list_files", `{"glob":"*.go"}`)
	if err != nil || !strings.Contains(filesOut, "pkg/one.go") {
		t.Fatalf("list_files failed: %v, out=%s", err, filesOut)
	}

	incOut, err := reg.Execute(ctx, "get_incremental_diff", `{}`)
	if err != nil || !strings.Contains(incOut, "[L11] +    new1()") {
		t.Fatalf("get_incremental_diff failed: %v, out=%s", err, incOut)
	}

	// Below MinSeverity ("info" < "warning") should be skipped
	skipOut, err := reg.Execute(ctx, "add_inline_comment", `{"path":"app.go","line":11,"severity":"info","body":"nit"}`)
	if err != nil || !strings.Contains(skipOut, "skipped") || reg.State.CommentCount() != 0 {
		t.Fatalf("expected info comment to be skipped, err=%v out=%s count=%d", err, skipOut, reg.State.CommentCount())
	}

	// Critical comment should be staged and duplicated call skipped
	if _, err := reg.Execute(ctx, "add_inline_comment", `{"path":"app.go","line":11,"severity":"critical","body":"bug"}`); err != nil {
		t.Fatal(err)
	}
	dupOut, err := reg.Execute(ctx, "add_inline_comment", `{"path":"app.go","line":11,"severity":"critical","body":"bug"}`)
	if err != nil || !strings.Contains(dupOut, "duplicate") || reg.State.CommentCount() != 1 || !reg.State.HasCritical() {
		t.Fatalf("unexpected dedup/critical state: out=%s count=%d critical=%v", dupOut, reg.State.CommentCount(), reg.State.HasCritical())
	}

	// Out-of-diff-hunk line should be routed to OutOfDiffNotes instead of failing
	outOfDiff, err := reg.Execute(ctx, "add_inline_comment", `{"path":"app.go","line":999,"severity":"warning","body":"outside hunk"}`)
	if err != nil || !strings.Contains(outOfDiff, "outside diff hunks") || reg.State.CommentCount() != 1 || len(reg.State.OutOfDiffNotes) != 1 {
		t.Fatalf("expected out-of-diff note routing, err=%v out=%s notes=%v", err, outOfDiff, reg.State.OutOfDiffNotes)
	}

	// inspect_go_symbols should parse Go AST
	symOut, err := reg.Execute(ctx, "inspect_go_symbols", `{"path":"pkg/one.go"}`)
	if err != nil || !strings.Contains(symOut, "package pkg") {
		t.Fatalf("inspect_go_symbols failed: %v, out=%s", err, symOut)
	}
}

func TestSearchCodeSkipsSymlinks(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	secretPath := filepath.Join(outside, "secret.yaml")
	if err := os.WriteFile(secretPath, []byte("token: SUPER_SECRET_HOST_TOKEN\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secretPath, filepath.Join(root, "leak.yaml")); err != nil {
		t.Skipf("symlinks not supported: %v", err)
	}
	reg := NewRegistry(Params{WorktreeDir: root})
	out, err := reg.Execute(context.Background(), "search_code", `{"pattern":"SUPER_SECRET_HOST_TOKEN"}`)
	if err != nil {
		t.Fatalf("search_code failed: %v", err)
	}
	if strings.Contains(out, "SUPER_SECRET_HOST_TOKEN") {
		t.Fatalf("search_code must not follow symlinks outside worktree, got: %s", out)
	}
}
