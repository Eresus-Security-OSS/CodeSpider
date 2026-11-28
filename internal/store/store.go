// Package store provides durable, zero-dependency JSON state persistence for the 24/7 daemon.
package store

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Eresus-Security-OSS/CodeSpider/internal/evidence"
)

// RunRecord captures the outcome of a single agent review or reply run.
type RunRecord struct {
	PRKey          string             `json:"pr_key"`
	Kind           string             `json:"kind"`
	HeadSHA        string             `json:"head_sha"`
	Model          string             `json:"model,omitempty"`
	Verdict        string             `json:"verdict,omitempty"`
	StepsUsed      int                `json:"steps_used"`
	TokensUsed     int                `json:"tokens_used"`
	InlineComments int                `json:"inline_comments"`
	Findings       []evidence.Finding `json:"findings,omitempty"`
	Stages         []string           `json:"stages,omitempty"`
	DurationMs     int64              `json:"duration_ms,omitempty"`
	Status         string             `json:"status"` // success, failed, canceled
	Error          string             `json:"error,omitempty"`
	FinishedAt     time.Time          `json:"finished_at"`
}

type persistedState struct {
	ReviewedSHAs map[string]string `json:"reviewed_shas"`
	RecentRuns   []RunRecord       `json:"recent_runs"`
	PausedPRs    map[string]bool   `json:"paused_prs,omitempty"`
}

// Store persists reviewed commit SHAs and recent run audit logs atomically to disk.
type Store struct {
	mu    sync.Mutex
	path  string
	state persistedState
}

// Open loads or initializes the state file under dataDir.
func Open(dataDir string) (*Store, error) {
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return nil, err
	}
	p := filepath.Join(dataDir, "state.json")
	s := &Store{
		path: p,
		state: persistedState{
			ReviewedSHAs: make(map[string]string),
		},
	}
	raw, err := os.ReadFile(p)
	if err == nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, &s.state); err != nil {
			return nil, fmt.Errorf("corrupt state file %s: %w", p, err)
		}
		if s.state.ReviewedSHAs == nil {
			s.state.ReviewedSHAs = make(map[string]string)
		}
	} else if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	return s, nil
}

// PRKey formats a canonical identifier for a pull request.
func PRKey(owner, repo string, prNumber int64) string {
	return fmt.Sprintf("%s/%s#%d", owner, repo, prNumber)
}

// maxPausedPRs bounds the persisted pause set so a flood of /pause comments cannot grow state.json without limit.
const maxPausedPRs = 5000

// IsPaused reports whether automatic reviews are paused for prKey. It is safe on a nil Store.
func (s *Store) IsPaused(prKey string) bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state.PausedPRs[prKey]
}

// SetPaused pauses or resumes automatic reviews for prKey and persists the change.
// It reports whether the paused state actually changed.
func (s *Store) SetPaused(prKey string, paused bool) (changed bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state.PausedPRs[prKey] == paused {
		return false, nil
	}
	if paused {
		if len(s.state.PausedPRs) >= maxPausedPRs {
			return false, fmt.Errorf("too many paused PRs (limit %d)", maxPausedPRs)
		}
		if s.state.PausedPRs == nil {
			s.state.PausedPRs = make(map[string]bool)
		}
		s.state.PausedPRs[prKey] = true
	} else {
		delete(s.state.PausedPRs, prKey)
	}
	if err := s.saveLocked(); err != nil {
		return false, err
	}
	return true, nil
}

// IsAlreadyReviewed returns true if the given SHA was already reviewed for this PR.
func (s *Store) IsAlreadyReviewed(prKey, sha string) bool {
	if sha == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state.ReviewedSHAs[prKey] == sha
}

// LastReviewedSHA returns the most recently reviewed commit SHA for prKey, or "".
func (s *Store) LastReviewedSHA(prKey string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state.ReviewedSHAs[prKey]
}

// ReviewedPRCount returns the number of distinct PRs with a recorded reviewed SHA.
func (s *Store) ReviewedPRCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.state.ReviewedSHAs)
}

// RecordRun persists the result of an agent run and updates the reviewed SHA on success.
func (s *Store) RecordRun(rec RunRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if rec.Status == "success" && rec.Kind == "pr_review" && rec.HeadSHA != "" {
		s.state.ReviewedSHAs[rec.PRKey] = rec.HeadSHA
	}
	const maxRecentRuns = 100
	if len(s.state.RecentRuns) < maxRecentRuns {
		s.state.RecentRuns = append(s.state.RecentRuns, rec)
	} else {
		keep := s.state.RecentRuns[len(s.state.RecentRuns)-(maxRecentRuns-1):]
		copy(s.state.RecentRuns, keep)
		clear(s.state.RecentRuns[maxRecentRuns:])
		s.state.RecentRuns = s.state.RecentRuns[:maxRecentRuns]
		s.state.RecentRuns[maxRecentRuns-1] = rec
	}
	return s.saveLocked()
}

// RecentRuns returns a copy of the most recent run records.
func (s *Store) RecentRuns() []RunRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]RunRecord, len(s.state.RecentRuns))
	copy(out, s.state.RecentRuns)
	return out
}

// ListRuns returns newest-first paginated run records matching optional status and repo filters.
func (s *Store) ListRuns(offset, limit int, statusFilter, repoFilter string) ([]RunRecord, int) {
	if s == nil {
		return nil, 0
	}
	if limit <= 0 || limit > 100 {
		limit = 25
	}
	if offset < 0 {
		offset = 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	var filtered []RunRecord
	for i := len(s.state.RecentRuns) - 1; i >= 0; i-- {
		r := s.state.RecentRuns[i]
		if statusFilter != "" && !strings.EqualFold(r.Status, statusFilter) {
			continue
		}
		if repoFilter != "" && !strings.Contains(strings.ToLower(r.PRKey), strings.ToLower(repoFilter)) {
			continue
		}
		filtered = append(filtered, r)
	}
	total := len(filtered)
	if offset >= total {
		return nil, total
	}
	end := offset + limit
	if end > total {
		end = total
	}
	return filtered[offset:end], total
}

func (s *Store) saveLocked() error {
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
