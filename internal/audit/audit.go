// Package audit writes append-only security and authorization audit logs.
package audit

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Event records an authorization or security-relevant daemon action.
type Event struct {
	Timestamp time.Time `json:"timestamp"`
	Actor     string    `json:"actor,omitempty"`
	PRKey     string    `json:"pr_key,omitempty"`
	Action    string    `json:"action"`
	Decision  string    `json:"decision"` // allow, deny, info
	Reason    string    `json:"reason,omitempty"`
}

// Logger appends JSONL audit records to <dataDir>/audit.jsonl.
type Logger struct {
	mu   sync.Mutex
	path string
}

// NewLogger creates an audit Logger rooted at dataDir. If dataDir is empty, logging is a no-op.
func NewLogger(dataDir string) *Logger {
	if dataDir == "" {
		return nil
	}
	return &Logger{
		path: filepath.Join(dataDir, "audit.jsonl"),
	}
}

// Log writes an audit event atomically under mutex. Nil-safe.
func (l *Logger) Log(ev Event) {
	if l == nil || l.path == "" {
		return
	}
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now().UTC()
	}
	raw, err := json.Marshal(ev)
	if err != nil {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	_ = os.MkdirAll(filepath.Dir(l.path), 0o755)
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.Write(append(raw, '\n'))
}

// ReadRecent returns up to limit most recent audit events (newest first).
func (l *Logger) ReadRecent(limit int) ([]Event, error) {
	if l == nil || l.path == "" {
		return nil, nil
	}
	if limit <= 0 || limit > 200 {
		limit = 100
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	f, err := os.Open(l.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	var all []Event
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 8*1024), 512*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var ev Event
		if json.Unmarshal(line, &ev) == nil {
			all = append(all, ev)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(all) > limit {
		all = all[len(all)-limit:]
	}
	// Reverse to newest-first.
	for i, j := 0, len(all)-1; i < j; i, j = i+1, j-1 {
		all[i], all[j] = all[j], all[i]
	}
	return all, nil
}
