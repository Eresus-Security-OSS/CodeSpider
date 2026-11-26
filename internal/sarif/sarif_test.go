package sarif

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Eresus-Security-OSS/CodeSpider/internal/evidence"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/security"
)

func TestMarshalSARIF(t *testing.T) {
	raw, err := Marshal([]evidence.Finding{{
		RuleID:      "CS-SEC-001",
		Fingerprint: "abcd1234",
		Severity:    "critical",
		State:       evidence.StateStaticallySupported,
		Path:        "api/handler.go",
		StartLine:   12,
		EndLine:     12,
		Body:        "Command injection",
		Evidence:    []string{"exec.Command(sh, -c)"},
	}}, []security.Finding{{
		File:          "cfg.go",
		Line:          3,
		Kind:          "AWS Access Key",
		MaskedPreview: "AKIA...MP",
		InHistoryOnly: true,
	}})
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("invalid SARIF JSON: %v", err)
	}
	if doc["version"] != "2.1.0" || !strings.Contains(string(raw), "statically_supported") || !strings.Contains(string(raw), "CS-SECRET-001") {
		t.Fatalf("unexpected SARIF output:\n%s", string(raw))
	}
}
