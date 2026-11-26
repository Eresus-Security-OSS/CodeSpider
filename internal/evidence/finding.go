// Package evidence defines explicit, verifiable evidence states for code review findings.
package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// State represents the epistemic verification level of a finding.
type State string

const (
	StateCandidate                State = "candidate"
	StateStaticallySupported      State = "statically_supported"
	StateModelCorroborated        State = "model_corroborated"
	StateTestReproduced           State = "test_reproduced"
	StateDifferentiallyReproduced State = "differentially_reproduced"
	StateHumanConfirmed           State = "human_confirmed"
	StateRefuted                  State = "refuted"
	StateInconclusive             State = "inconclusive"
)

// Finding models a review finding with explicit evidence, counter-evidence, and limitations.
type Finding struct {
	ID              string   `json:"id,omitempty"`
	Fingerprint     string   `json:"fingerprint"`
	RuleID          string   `json:"rule_id,omitempty"`
	Category        string   `json:"category,omitempty"`
	Severity        string   `json:"severity"` // info, warning, critical
	State           State    `json:"state"`
	Path            string   `json:"path"`
	StartLine       int64    `json:"start_line,omitempty"`
	EndLine         int64    `json:"end_line"`
	Symbol          string   `json:"symbol,omitempty"`
	CommitSHA       string   `json:"commit_sha,omitempty"`
	Title           string   `json:"title,omitempty"`
	Body            string   `json:"body"`
	Suggestion      string   `json:"suggestion,omitempty"`
	Evidence        []string `json:"evidence,omitempty"`
	CounterEvidence []string `json:"counter_evidence,omitempty"`
	Limitations     []string `json:"limitations,omitempty"`
	PreExisting     bool     `json:"pre_existing,omitempty"`
}

// ComputeFingerprint generates a stable 16-hex-char identifier for deduplication and review memory.
func ComputeFingerprint(ruleID, category, path, symbol string) string {
	h := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(ruleID)) + "\x00" +
		strings.ToLower(strings.TrimSpace(category)) + "\x00" +
		strings.TrimSpace(path) + "\x00" +
		strings.TrimSpace(symbol)))
	return hex.EncodeToString(h[:8])
}

// FormatBadge renders a concise, honest badge reflecting the finding's verification state.
// Never labels LLM agreement as "verified".
func FormatBadge(st State) string {
	switch st {
	case StateStaticallySupported:
		return "[STATICALLY SUPPORTED]"
	case StateModelCorroborated:
		return "[MODEL CORROBORATED]"
	case StateTestReproduced:
		return "[TEST REPRODUCED]"
	case StateDifferentiallyReproduced:
		return "[DIFFERENTIALLY REPRODUCED]"
	case StateHumanConfirmed:
		return "[HUMAN CONFIRMED]"
	case StateRefuted:
		return "[REFUTED]"
	case StateInconclusive:
		return "[INCONCLUSIVE]"
	default:
		return "[CANDIDATE]"
	}
}

// ApplyTestOutcome updates a finding's evidence state from differential test execution.
// An unsuccessful reproduction never marks a finding as refuted; it marks it inconclusive.
func (f *Finding) ApplyTestOutcome(basePassed, headFailed, executed bool, note string) {
	if !executed {
		f.State = StateInconclusive
		if note != "" {
			f.Limitations = append(f.Limitations, note)
		}
		return
	}
	if !headFailed {
		f.State = StateInconclusive
		f.Limitations = append(f.Limitations, "reproduction test passed on head; issue may depend on unmodeled inputs or environment")
		return
	}
	if basePassed {
		f.State = StateDifferentiallyReproduced
		f.Evidence = append(f.Evidence, "differential test passed on base commit and failed on head commit")
		return
	}
	f.State = StateTestReproduced
	f.PreExisting = true
	f.Evidence = append(f.Evidence, "test failed on both base and head commits (pre-existing issue)")
}

// RenderInlineBody formats a finding into a clean Gitea inline comment body.
func (f Finding) RenderInlineBody() string {
	var b strings.Builder
	sev := strings.ToUpper(strings.TrimSpace(f.Severity))
	if sev == "" {
		sev = "INFO"
	}
	fmt.Fprintf(&b, "**[%s]** **%s**", sev, FormatBadge(f.State))
	if f.StartLine > 0 && f.StartLine < f.EndLine {
		fmt.Fprintf(&b, " *(Lines %d–%d)*", f.StartLine, f.EndLine)
	}
	b.WriteByte(' ')
	b.WriteString(strings.TrimSpace(f.Body))
	if len(f.Evidence) > 0 {
		b.WriteString("\n\n**Evidence:** ")
		b.WriteString(strings.Join(f.Evidence, "; "))
	}
	if len(f.Limitations) > 0 {
		b.WriteString("\n**Limitations:** ")
		b.WriteString(strings.Join(f.Limitations, "; "))
	}
	if strings.TrimSpace(f.Suggestion) != "" {
		fmt.Fprintf(&b, "\n\n```suggestion\n%s\n```", strings.TrimRight(f.Suggestion, "\r\n"))
	}
	return b.String()
}
