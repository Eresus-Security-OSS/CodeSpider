// Package update checks whether a newer CodeSpider release exists.
//
// CodeSpider is distributed as a container image (and from source), not as downloadable
// binaries, so this package only reports availability and never replaces the running
// executable. Releases are the stable "vMAJOR.MINOR.PATCH" git tags of the repository,
// which are also the tags that trigger the image build.
//
// Contract: GET {APIBase}/repos/{Repo}/tags?per_page=100 returns a JSON array of objects
// with a "name" field (GitHub REST v3). Verified against the public API shape on 2026-11-28.
package update

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// DefaultRepo is the repository whose tags define releases.
	DefaultRepo = "Eresus-Security-OSS/CodeSpider"
	// DefaultAPIBase is the GitHub REST API root.
	DefaultAPIBase = "https://api.github.com"

	maxResponseBytes = 1 << 20
	requestTimeout   = 10 * time.Second
)

var (
	// ErrDevBuild means the running binary has no release version, so it cannot be compared.
	ErrDevBuild = errors.New("development build: no release version to compare")

	semverRe = regexp.MustCompile(`^v?(\d+)\.(\d+)\.(\d+)$`)
)

// Version is a parsed stable semantic version.
type Version struct{ Major, Minor, Patch int }

// ParseVersion parses "v1.2.3" or "1.2.3". Pre-release and build suffixes are rejected so
// they can never be offered as an update.
func ParseVersion(s string) (Version, bool) {
	m := semverRe.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return Version{}, false
	}
	var v Version
	var err error
	if v.Major, err = strconv.Atoi(m[1]); err != nil {
		return Version{}, false
	}
	if v.Minor, err = strconv.Atoi(m[2]); err != nil {
		return Version{}, false
	}
	if v.Patch, err = strconv.Atoi(m[3]); err != nil {
		return Version{}, false
	}
	return v, true
}

// Less reports whether v sorts before o.
func (v Version) Less(o Version) bool {
	if v.Major != o.Major {
		return v.Major < o.Major
	}
	if v.Minor != o.Minor {
		return v.Minor < o.Minor
	}
	return v.Patch < o.Patch
}

func (v Version) String() string { return fmt.Sprintf("v%d.%d.%d", v.Major, v.Minor, v.Patch) }

// Status is the result of one update check.
type Status struct {
	Current         string    `json:"current"`
	Latest          string    `json:"latest,omitempty"`
	UpdateAvailable bool      `json:"update_available"`
	CheckedAt       time.Time `json:"checked_at,omitempty"`
	Error           string    `json:"error,omitempty"`
}

// Checker queries the tag list of Repo on APIBase.
type Checker struct {
	APIBase string
	Repo    string
	HTTP    *http.Client
}

// NewChecker returns a Checker for the official repository.
func NewChecker() *Checker {
	return &Checker{APIBase: DefaultAPIBase, Repo: DefaultRepo, HTTP: &http.Client{Timeout: requestTimeout}}
}

// Check compares current against the highest stable tag. A development build (any current
// that is not a stable version) returns ErrDevBuild without touching the network.
func (c *Checker) Check(ctx context.Context, current string) (Status, error) {
	st := Status{Current: current, CheckedAt: time.Now().UTC()}
	cur, ok := ParseVersion(current)
	if !ok {
		st.Error = ErrDevBuild.Error()
		return st, ErrDevBuild
	}
	latest, err := c.latestTag(ctx)
	if err != nil {
		st.Error = err.Error()
		return st, err
	}
	st.Latest = latest.String()
	st.UpdateAvailable = cur.Less(latest)
	return st, nil
}

func (c *Checker) latestTag(ctx context.Context) (Version, error) {
	client := c.HTTP
	if client == nil {
		client = &http.Client{Timeout: requestTimeout}
	}
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()

	url := strings.TrimRight(c.APIBase, "/") + "/repos/" + c.Repo + "/tags?per_page=100"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return Version{}, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "codespider-update-check")

	resp, err := client.Do(req)
	if err != nil {
		return Version{}, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return Version{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return Version{}, fmt.Errorf("tag list request failed: %s", resp.Status)
	}
	var tags []struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(body, &tags); err != nil {
		return Version{}, fmt.Errorf("decode tag list: %w", err)
	}
	var best Version
	found := false
	for _, t := range tags {
		v, ok := ParseVersion(t.Name)
		if !ok {
			continue
		}
		if !found || best.Less(v) {
			best, found = v, true
		}
	}
	if !found {
		return Version{}, errors.New("no stable release tags found")
	}
	return best, nil
}

// Monitor periodically re-checks for updates and keeps the latest Status for readers
// such as the /status endpoint.
type Monitor struct {
	checker *Checker
	current string

	mu   sync.RWMutex
	last Status
}

// NewMonitor creates a Monitor. checker may be nil to use the official repository.
func NewMonitor(checker *Checker, current string) *Monitor {
	if checker == nil {
		checker = NewChecker()
	}
	return &Monitor{checker: checker, current: current, last: Status{Current: current}}
}

// Status returns the most recent check result. It is safe on a nil Monitor.
func (m *Monitor) Status() Status {
	if m == nil {
		return Status{}
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.last
}

// Run checks immediately and then every interval until ctx ends. onNewer is called once per
// newly seen latest version, never for the same version twice.
func (m *Monitor) Run(ctx context.Context, interval time.Duration, onNewer func(Status), onError func(error)) {
	if interval <= 0 {
		return
	}
	announced := ""
	check := func() {
		st, err := m.checker.Check(ctx, m.current)
		if ctx.Err() != nil {
			return // shutting down: do not replace a good status with a cancellation error
		}
		m.mu.Lock()
		if err != nil && !errors.Is(err, ErrDevBuild) {
			// A transient failure must not hide an update that an earlier check already found.
			st.Latest, st.UpdateAvailable = m.last.Latest, m.last.UpdateAvailable
		}
		m.last = st
		m.mu.Unlock()
		if err != nil {
			if onError != nil && !errors.Is(err, ErrDevBuild) {
				onError(err)
			}
			return
		}
		if st.UpdateAvailable && st.Latest != announced {
			announced = st.Latest
			if onNewer != nil {
				onNewer(st)
			}
		}
	}
	check()
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			check()
		}
	}
}
