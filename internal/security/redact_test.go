package security

import (
	"strings"
	"testing"
)

func TestRedactText(t *testing.T) {
	in := "Authorization: Bearer super-secret-jwt and https://oauth2:mysecretpass@gitea.local/a/b.git and ghp_1234567890abcdef1234 and AKIAZ9X8C7V6B5N4M3Q2"
	got := RedactText(in, "custom-secret-value")
	for _, leaked := range []string{"super-secret-jwt", "mysecretpass", "ghp_1234567890abcdef1234", "AKIAZ9X8C7V6B5N4M3Q2"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("expected %q to be redacted in %q", leaked, got)
		}
	}
	if !strings.Contains(got, "[REDACTED]") {
		t.Fatalf("expected [REDACTED] marker in %q", got)
	}
	if gotLit := RedactText("err: custom-secret-value failed", "custom-secret-value"); strings.Contains(gotLit, "custom-secret-value") {
		t.Fatalf("expected custom literal to be redacted: %q", gotLit)
	}
}
