// Package store provides durable, zero-dependency JSON state persistence for the 24/7 daemon.
package store

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// RunRecord captures the outcome of a single agent review or reply run.
type RunRecord struct {
	PRKey          string    `json:"pr_key"`
	Kind           string    `json:"kind"`
	HeadSHA        string    `json:"head_sha"`
	StepsUsed      int       `json:"steps_used"`
	TokensUsed     int       `json:"tokens_used"`
	InlineComments int       `json:"inline_comments"`
	Status         string    `json:"status"` // success, failed, canceled
	Error          string    `json:"error,omitempty"`
	FinishedAt     time.Time `json:"finished_at"`
}

type persistedState struct {
	ReviewedSHAs map[string]string `json:"reviewed_shas"`
	RecentRuns   []RunRecord       `json:"recent_runs"`
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

// IsAlreadyReviewed returns true if the given SHA was already reviewed for this PR.
func (s *Store) IsAlreadyReviewed(prKey, sha string) bool {
	if sha == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state.ReviewedSHAs[prKey] == sha
}

// RecordRun persists the result of an agent run and updates the reviewed SHA on success.
func (s *Store) RecordRun(rec RunRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if rec.Status == "success" && rec.Kind == "pr_review" && rec.HeadSHA != "" {
		s.state.ReviewedSHAs[rec.PRKey] = rec.HeadSHA
	}
	s.state.RecentRuns = append(s.state.RecentRuns, rec)
	if len(s.state.RecentRuns) > 100 {
		s.state.RecentRuns = s.state.RecentRuns[len(s.state.RecentRuns)-100:]
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

func (s *Store) saveLocked() error {
	raw, err := json.MarshalIndent(s.state, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}
