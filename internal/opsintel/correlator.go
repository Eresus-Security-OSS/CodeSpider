// Package opsintel correlates optional production telemetry (error rates, latency regressions,
// exception fingerprints, and flaky CI tests) with PR changed paths while redacting PII/secrets.
package opsintel

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Eresus-Security-OSS/CodeSpider/internal/security"
)

// Signal represents a production or CI reliability signal tied to a file/path prefix or symbol.
type Signal struct {
	Source     string  `json:"source"` // prometheus, opentelemetry, sentry, ci
	Repo       string  `json:"repo,omitempty"`
	PathPrefix string  `json:"path_prefix"`
	Symbol     string  `json:"symbol,omitempty"`
	Metric     string  `json:"metric"` // error_rate, p99_ms, exception, flaky_test
	Value      float64 `json:"value,omitempty"`
	Summary    string  `json:"summary"`
}

// RiskAnnotation highlights production context on paths touched by a PR.
type RiskAnnotation struct {
	Path    string `json:"path"`
	Source  string `json:"source"`
	Summary string `json:"summary"`
}

// Correlator matches sanitized production signals against PR changed paths.
type Correlator struct {
	signals         []Signal
	allowLLMSharing bool
}

// Load reads an optional JSON telemetry snapshot file and scrubs secrets/PII from all fields.
func Load(path string, allowLLMSharing bool) (*Correlator, error) {
	c := &Correlator{allowLLMSharing: allowLLMSharing}
	if strings.TrimSpace(path) == "" {
		return c, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return c, nil
		}
		return nil, err
	}
	var signals []Signal
	if err := json.Unmarshal(raw, &signals); err != nil {
		return nil, fmt.Errorf("parse telemetry %s: %w", path, err)
	}
	for i := range signals {
		signals[i].Summary = security.RedactText(signals[i].Summary)
		signals[i].Symbol = security.RedactText(signals[i].Symbol)
	}
	c.signals = signals
	return c, nil
}

// Correlate returns risk annotations for changedPaths and optional redacted LLM context
// (only populated when allow_llm_telemetry_sharing is explicitly enabled).
func (c *Correlator) Correlate(repoSlug string, changedPaths []string) (annotations []RiskAnnotation, llmPromptContext string) {
	if c == nil || len(c.signals) == 0 || len(changedPaths) == 0 {
		return nil, ""
	}
	for _, sig := range c.signals {
		if sig.Repo != "" && sig.Repo != "*" && !strings.EqualFold(sig.Repo, repoSlug) {
			continue
		}
		prefix := filepath.ToSlash(strings.TrimSpace(sig.PathPrefix))
		for _, cp := range changedPaths {
			slash := filepath.ToSlash(cp)
			if prefix == "" || strings.HasPrefix(slash, prefix) {
				annotations = append(annotations, RiskAnnotation{
					Path:    slash,
					Source:  sig.Source,
					Summary: sig.Summary,
				})
				break
			}
		}
	}
	if !c.allowLLMSharing || len(annotations) == 0 {
		return annotations, ""
	}
	var b strings.Builder
	b.WriteString("### Sanitized Production Telemetry Signals\n")
	for _, a := range annotations {
		fmt.Fprintf(&b, "- [%s] `%s`: %s\n", a.Source, a.Path, a.Summary)
	}
	return annotations, b.String()
}
