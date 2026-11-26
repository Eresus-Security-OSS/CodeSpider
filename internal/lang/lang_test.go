package lang

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultRegistryPolyglotAnalysis(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\n\nfunc Hello(name string) string { return name }\n"), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "app.py"), []byte("import os\n\ndef handle_user(uid: int) -> str:\n    return str(uid)\n\ndef test_handle_user():\n    assert handle_user(1) == '1'\n"), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "api.ts"), []byte("import { req } from './http';\nexport interface User { id: string }\nexport function getUser(id: string): User { return { id }; }\n"), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "lib.rs"), []byte("use std::fmt;\npub struct Token { pub id: String }\npub fn verify(t: &Token) -> bool { true }\n#[test]\nfn works() {}\n"), 0o644)

	reg := NewDefaultRegistry()
	statuses := reg.Statuses()
	if len(statuses) != 4 {
		t.Fatalf("expected 4 language statuses, got %d", len(statuses))
	}

	results, err := reg.AnalyzeFiles(context.Background(), dir, []string{"main.go", "app.py", "api.ts", "lib.rs"})
	if err != nil {
		t.Fatalf("AnalyzeFiles failed: %v", err)
	}
	if len(results) != 4 {
		t.Fatalf("expected 4 file analyses, got %d", len(results))
	}

	byFile := make(map[string]FileAnalysis)
	for _, r := range results {
		byFile[r.File] = r
	}
	if len(byFile["main.go"].Contracts) == 0 || !byFile["main.go"].Capabilities.Has(CapTypes) {
		t.Fatalf("unexpected Go analysis: %+v", byFile["main.go"])
	}
	if len(byFile["app.py"].Tests) != 1 || byFile["app.py"].Capabilities.Has(CapTypes) {
		t.Fatalf("unexpected Python analysis (must report tests and NOT claim CapTypes): %+v", byFile["app.py"])
	}
	if len(byFile["api.ts"].Contracts) < 2 {
		t.Fatalf("unexpected TS analysis: %+v", byFile["api.ts"])
	}
	if len(byFile["lib.rs"].Tests) != 1 || len(byFile["lib.rs"].Contracts) < 2 {
		t.Fatalf("unexpected Rust analysis: %+v", byFile["lib.rs"])
	}
}
