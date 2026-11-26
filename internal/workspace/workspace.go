// Package workspace manages local git mirror caches and ephemeral PR worktrees.
package workspace

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
)

// Manager maintains bare git mirrors and checks out isolated worktrees per PR commit.
type Manager struct {
	baseDir string
	token   string
	mu      sync.Mutex
	repoMu  map[string]*sync.Mutex
}

// NewManager creates a workspace Manager rooted at baseDir.
func NewManager(baseDir, giteaToken string) *Manager {
	return &Manager{
		baseDir: baseDir,
		token:   giteaToken,
		repoMu:  make(map[string]*sync.Mutex),
	}
}

// CheckoutPR ensures the repo mirror is up to date and creates a temporary worktree at sha.
// The returned cleanup function removes the temporary worktree.
func (m *Manager) CheckoutPR(ctx context.Context, owner, repo, cloneURL, sha string) (worktreeDir string, cleanup func(), err error) {
	if cloneURL == "" {
		return "", func() {}, fmt.Errorf("empty cloneURL for %s/%s", owner, repo)
	}
	lock := m.lockFor(owner + "/" + repo)
	lock.Lock()
	defer lock.Unlock()

	mirrorDir := filepath.Join(m.baseDir, "mirrors", sanitize(owner), sanitize(repo)+".git")
	if err := os.MkdirAll(filepath.Dir(mirrorDir), 0o755); err != nil {
		return "", func() {}, err
	}

	authURL := injectToken(cloneURL, m.token)

	if _, statErr := os.Stat(mirrorDir); os.IsNotExist(statErr) {
		if err := runGit(ctx, "", "clone", "--bare", authURL, mirrorDir); err != nil {
			return "", func() {}, fmt.Errorf("git clone --bare: %w", err)
		}
	} else {
		if err := runGit(ctx, mirrorDir, "fetch", "--prune", authURL, "+refs/*:refs/*"); err != nil {
			return "", func() {}, fmt.Errorf("git fetch: %w", err)
		}
	}

	wtBase := filepath.Join(m.baseDir, "worktrees")
	if err := os.MkdirAll(wtBase, 0o755); err != nil {
		return "", func() {}, err
	}
	wtDir, err := os.MkdirTemp(wtBase, sanitize(owner)+"-"+sanitize(repo)+"-")
	if err != nil {
		return "", func() {}, err
	}

	target := sha
	if target == "" {
		target = "HEAD"
	}
	if err := runGit(ctx, mirrorDir, "worktree", "add", "--detach", wtDir, target); err != nil {
		_ = os.RemoveAll(wtDir)
		return "", func() {}, fmt.Errorf("git worktree add: %w", err)
	}

	cleanupFn := func() {
		lock.Lock()
		defer lock.Unlock()
		_ = runGit(context.Background(), mirrorDir, "worktree", "remove", "--force", wtDir)
		_ = os.RemoveAll(wtDir)
	}
	return wtDir, cleanupFn, nil
}

// CommitAndPush stages all changes in worktreeDir, commits them, and pushes to headBranch on cloneURL.
func (m *Manager) CommitAndPush(ctx context.Context, worktreeDir, cloneURL, headBranch, authorName, commitMsg string) (string, error) {
	if worktreeDir == "" || cloneURL == "" || headBranch == "" {
		return "", fmt.Errorf("worktreeDir, cloneURL, and headBranch are required")
	}
	if strings.TrimSpace(commitMsg) == "" {
		return "", fmt.Errorf("commit message is required")
	}
	if authorName == "" {
		authorName = "CodeSpider"
	}

	if err := runGit(ctx, worktreeDir, "add", "-A"); err != nil {
		return "", fmt.Errorf("git add: %w", err)
	}

	statusCmd := exec.CommandContext(ctx, "git", "status", "--porcelain")
	statusCmd.Dir = worktreeDir
	statusOut, err := statusCmd.Output()
	if err != nil {
		return "", fmt.Errorf("git status: %w", err)
	}
	if len(strings.TrimSpace(string(statusOut))) == 0 {
		return "", fmt.Errorf("no modified files to commit")
	}

	email := strings.ToLower(strings.ReplaceAll(authorName, " ", "")) + "@codespider.local"
	if err := runGit(ctx, worktreeDir,
		"-c", "user.name="+authorName,
		"-c", "user.email="+email,
		"commit", "-m", commitMsg,
	); err != nil {
		return "", fmt.Errorf("git commit: %w", err)
	}

	shaCmd := exec.CommandContext(ctx, "git", "rev-parse", "HEAD")
	shaCmd.Dir = worktreeDir
	shaOut, err := shaCmd.Output()
	if err != nil {
		return "", fmt.Errorf("git rev-parse: %w", err)
	}
	newSHA := strings.TrimSpace(string(shaOut))

	authURL := injectToken(cloneURL, m.token)
	refspec := fmt.Sprintf("HEAD:refs/heads/%s", headBranch)
	if err := runGit(ctx, worktreeDir, "push", authURL, refspec); err != nil {
		return "", fmt.Errorf("git push: %w", err)
	}
	return newSHA, nil
}

// ResolveSafePath resolves relPath inside rootDir and rejects absolute paths or traversal outside rootDir.
func ResolveSafePath(rootDir, relPath string) (string, error) {
	if filepath.IsAbs(relPath) {
		return "", fmt.Errorf("path must be relative: %s", relPath)
	}
	cleanRoot, err := filepath.Abs(rootDir)
	if err != nil {
		return "", err
	}
	joined := filepath.Clean(filepath.Join(cleanRoot, relPath))
	rel, err := filepath.Rel(cleanRoot, joined)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path escapes workspace: %s", relPath)
	}
	return joined, nil
}

func (m *Manager) lockFor(key string) *sync.Mutex {
	m.mu.Lock()
	defer m.mu.Unlock()
	if l, ok := m.repoMu[key]; ok {
		return l
	}
	l := &sync.Mutex{}
	m.repoMu[key] = l
	return l
}

func runGit(ctx context.Context, dir string, args ...string) error {
	cmd := exec.CommandContext(ctx, "git", args...)
	if dir != "" {
		cmd.Dir = dir
	}
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func injectToken(rawURL, token string) string {
	if token == "" {
		return rawURL
	}
	u, err := url.Parse(rawURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return rawURL
	}
	u.User = url.UserPassword("oauth2", token)
	return u.String()
}

func sanitize(s string) string {
	s = strings.ReplaceAll(s, "..", "_")
	s = strings.ReplaceAll(s, "/", "_")
	return s
}
