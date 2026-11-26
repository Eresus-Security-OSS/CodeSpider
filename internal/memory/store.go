// Package memory implements persistent repository and organization-level review memory
// with explicit authorization gates, expiration/versioning, incident context, and policy simulation.
package memory

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Eresus-Security-OSS/CodeSpider/internal/evidence"
)

// ErrUnauthorizedMemoryMutation is returned when an untrusted actor attempts to mutate review memory.
var ErrUnauthorizedMemoryMutation = errors.New("unauthorized review memory mutation")

// FeedbackRecord stores explicit human feedback on a finding fingerprint.
type FeedbackRecord struct {
	Fingerprint string     `json:"fingerprint"`
	Repo        string     `json:"repo"`   // "owner/repo" or "*"
	Status      string     `json:"status"` // accepted, rejected, false_positive, duplicate
	Reason      string     `json:"reason,omitempty"`
	RecordedBy  string     `json:"recorded_by"`
	CreatedAt   time.Time  `json:"created_at"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
}

// PolicyRule defines an approved repository or organization-wide review rule.
type PolicyRule struct {
	ID          string     `json:"id"`
	Version     int        `json:"version"`
	Scope       string     `json:"scope"` // "repo" or "org"
	Repo        string     `json:"repo"`  // "owner/repo" or "*"
	Pattern     string     `json:"pattern,omitempty"`
	Instruction string     `json:"instruction"`
	Severity    string     `json:"severity,omitempty"` // optional override or "suppress"
	ApprovedBy  string     `json:"approved_by"`
	UpdatedAt   time.Time  `json:"updated_at"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
}

// IncidentRecord captures a historical production incident for incident-aware reviews.
type IncidentRecord struct {
	ID         string    `json:"id"`
	Repo       string    `json:"repo"`
	PathPrefix string    `json:"path_prefix"`
	Summary    string    `json:"summary"`
	RootCause  string    `json:"root_cause,omitempty"`
	CommitSHA  string    `json:"commit_sha,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
}

// Snapshot is the serializable state of review memory.
type Snapshot struct {
	Feedback  map[string]FeedbackRecord `json:"feedback"`
	Rules     map[string]PolicyRule     `json:"rules"`
	Incidents []IncidentRecord          `json:"incidents"`
}

// SimulationResult summarizes how a proposed PolicyRule affects historical findings.
type SimulationResult struct {
	TotalEvaluated int      `json:"total_evaluated"`
	MatchedCount   int      `json:"matched_count"`
	SuppressedIDs  []string `json:"suppressed_ids,omitempty"`
}

// Store persists review feedback, approved rules, and incident history atomically.
type Store struct {
	mu    sync.RWMutex
	path  string
	state Snapshot
}

// Open initializes or loads review memory from dataDir/memory.json.
func Open(dataDir string) (*Store, error) {
	s := &Store{
		state: Snapshot{
			Feedback: make(map[string]FeedbackRecord),
			Rules:    make(map[string]PolicyRule),
		},
	}
	if dataDir == "" {
		return s, nil
	}
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return nil, err
	}
	s.path = filepath.Join(dataDir, "memory.json")
	raw, err := os.ReadFile(s.path)
	if err == nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, &s.state); err != nil {
			return nil, fmt.Errorf("corrupt memory file %s: %w", s.path, err)
		}
		if s.state.Feedback == nil {
			s.state.Feedback = make(map[string]FeedbackRecord)
		}
		if s.state.Rules == nil {
			s.state.Rules = make(map[string]PolicyRule)
		}
	} else if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	return s, nil
}

// RecordFeedback stores finding feedback; requires authorized=true.
func (s *Store) RecordFeedback(authorized bool, rec FeedbackRecord) error {
	if !authorized {
		return ErrUnauthorizedMemoryMutation
	}
	if strings.TrimSpace(rec.Fingerprint) == "" || strings.TrimSpace(rec.Status) == "" {
		return fmt.Errorf("fingerprint and status are required")
	}
	if rec.Repo == "" {
		rec.Repo = "*"
	}
	if rec.CreatedAt.IsZero() {
		rec.CreatedAt = time.Now().UTC()
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.Feedback[feedbackKey(rec.Repo, rec.Fingerprint)] = rec
	return s.saveLocked()
}

// UpsertRule adds or versions an approved policy rule; requires authorized=true.
func (s *Store) UpsertRule(authorized bool, rule PolicyRule) error {
	if !authorized {
		return ErrUnauthorizedMemoryMutation
	}
	if strings.TrimSpace(rule.ID) == "" || strings.TrimSpace(rule.Instruction) == "" {
		return fmt.Errorf("rule id and instruction are required")
	}
	if rule.Repo == "" {
		rule.Repo = "*"
	}
	rule.UpdatedAt = time.Now().UTC()

	s.mu.Lock()
	defer s.mu.Unlock()
	if prev, ok := s.state.Rules[rule.ID]; ok && rule.Version <= prev.Version {
		rule.Version = prev.Version + 1
	} else if rule.Version <= 0 {
		rule.Version = 1
	}
	s.state.Rules[rule.ID] = rule
	return s.saveLocked()
}

// RecordIncident stores a postmortem incident; requires authorized=true.
func (s *Store) RecordIncident(authorized bool, inc IncidentRecord) error {
	if !authorized {
		return ErrUnauthorizedMemoryMutation
	}
	if strings.TrimSpace(inc.ID) == "" || strings.TrimSpace(inc.Summary) == "" {
		return fmt.Errorf("incident id and summary are required")
	}
	if inc.CreatedAt.IsZero() {
		inc.CreatedAt = time.Now().UTC()
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.Incidents = append(s.state.Incidents, inc)
	return s.saveLocked()
}

// Delete removes a rule ID, feedback key, or incident ID; requires authorized=true.
func (s *Store) Delete(authorized bool, key string) (bool, error) {
	if !authorized {
		return false, ErrUnauthorizedMemoryMutation
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	removed := false
	if _, ok := s.state.Rules[key]; ok {
		delete(s.state.Rules, key)
		removed = true
	}
	for k, fb := range s.state.Feedback {
		if k == key || fb.Fingerprint == key {
			delete(s.state.Feedback, k)
			removed = true
		}
	}
	filtered := s.state.Incidents[:0]
	for _, inc := range s.state.Incidents {
		if inc.ID == key {
			removed = true
			continue
		}
		filtered = append(filtered, inc)
	}
	s.state.Incidents = filtered
	if removed {
		if err := s.saveLocked(); err != nil {
			return false, err
		}
	}
	return removed, nil
}

// Export returns a deep-enough copy of all stored memory records.
func (s *Store) Export() Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := Snapshot{
		Feedback:  make(map[string]FeedbackRecord, len(s.state.Feedback)),
		Rules:     make(map[string]PolicyRule, len(s.state.Rules)),
		Incidents: append([]IncidentRecord(nil), s.state.Incidents...),
	}
	for k, v := range s.state.Feedback {
		out.Feedback[k] = v
	}
	for k, v := range s.state.Rules {
		out.Rules[k] = v
	}
	return out
}

// FilterFindings suppresses non-expired false_positive/rejected/duplicate findings
// and marks human-accepted findings as StateHumanConfirmed.
func (s *Store) FilterFindings(repo string, findings []evidence.Finding) (kept []evidence.Finding, suppressed int) {
	if s == nil || len(findings) == 0 {
		return findings, 0
	}
	now := time.Now().UTC()

	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, f := range findings {
		fp := f.Fingerprint
		if fp == "" {
			fp = evidence.ComputeFingerprint(f.RuleID, f.Category, f.Path, f.Symbol)
		}
		fb, ok := s.lookupFeedbackLocked(repo, fp, now)
		if ok {
			switch strings.ToLower(fb.Status) {
			case "false_positive", "rejected", "duplicate":
				suppressed++
				continue
			case "accepted":
				f.State = evidence.StateHumanConfirmed
				f.Evidence = append(f.Evidence, "human feedback accepted by @"+fb.RecordedBy)
			}
		}
		kept = append(kept, f)
	}
	return kept, suppressed
}

// RelevantContext renders active memory rules and path-matching historical incidents for prompts.
func (s *Store) RelevantContext(repo string, changedPaths []string) string {
	if s == nil {
		return ""
	}
	now := time.Now().UTC()
	s.mu.RLock()
	defer s.mu.RUnlock()

	var rules []string
	for _, r := range s.state.Rules {
		if r.ExpiresAt != nil && now.After(*r.ExpiresAt) {
			continue
		}
		if r.Repo != "*" && !strings.EqualFold(r.Repo, repo) {
			continue
		}
		rules = append(rules, fmt.Sprintf("- [%s v%d] %s", r.ID, r.Version, r.Instruction))
	}

	var incidents []string
	for _, inc := range s.state.Incidents {
		if inc.Repo != "" && inc.Repo != "*" && !strings.EqualFold(inc.Repo, repo) {
			continue
		}
		if matchesAnyPrefix(inc.PathPrefix, changedPaths) {
			incidents = append(incidents, fmt.Sprintf("- [%s @ %s] %s", inc.ID, inc.PathPrefix, inc.Summary))
		}
	}

	if len(rules) == 0 && len(incidents) == 0 {
		return ""
	}
	var b strings.Builder
	if len(rules) > 0 {
		b.WriteString("### Approved Review Memory Rules\n")
		b.WriteString(strings.Join(rules, "\n"))
		b.WriteByte('\n')
	}
	if len(incidents) > 0 {
		b.WriteString("### Historical Incidents on Touched Paths\n")
		b.WriteString(strings.Join(incidents, "\n"))
		b.WriteByte('\n')
	}
	return b.String()
}

// SimulatePolicy evaluates a proposed PolicyRule against pastFindings without mutating state.
func SimulatePolicy(rule PolicyRule, pastFindings []evidence.Finding) SimulationResult {
	res := SimulationResult{TotalEvaluated: len(pastFindings)}
	pat := strings.ToLower(strings.TrimSpace(rule.Pattern))
	for _, f := range pastFindings {
		if pat == "" ||
			strings.Contains(strings.ToLower(f.Path), pat) ||
			strings.Contains(strings.ToLower(f.RuleID), pat) ||
			strings.Contains(strings.ToLower(f.Body), pat) {
			res.MatchedCount++
			if strings.EqualFold(rule.Severity, "suppress") {
				res.SuppressedIDs = append(res.SuppressedIDs, f.Fingerprint)
			}
		}
	}
	return res
}

func (s *Store) lookupFeedbackLocked(repo, fp string, now time.Time) (FeedbackRecord, bool) {
	for _, k := range []string{feedbackKey(repo, fp), feedbackKey("*", fp)} {
		if fb, ok := s.state.Feedback[k]; ok {
			if fb.ExpiresAt != nil && now.After(*fb.ExpiresAt) {
				continue
			}
			return fb, true
		}
	}
	return FeedbackRecord{}, false
}

func matchesAnyPrefix(prefix string, paths []string) bool {
	p := strings.TrimSpace(filepath.ToSlash(prefix))
	if p == "" {
		return len(paths) > 0
	}
	for _, cp := range paths {
		if strings.HasPrefix(filepath.ToSlash(cp), p) {
			return true
		}
	}
	return false
}

func feedbackKey(repo, fp string) string {
	return strings.ToLower(repo) + "::" + fp
}

func (s *Store) saveLocked() error {
	if s.path == "" {
		return nil
	}
	raw, err := json.MarshalIndent(s.state, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}
