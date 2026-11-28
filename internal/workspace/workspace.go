// Package workspace manages local git mirror caches and ephemeral PR worktrees.
package workspace

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
)

const maxDiffBytes = 5 << 20

// Manager maintains bare git mirrors and checks out isolated worktrees per PR commit.
type Manager struct {
	baseDir       string
	token         string
	allowedOrigin string
	mu            sync.Mutex
	repoMu        map[string]*sync.Mutex
}

// NewManager creates a workspace Manager rooted at baseDir.
func NewManager(baseDir, giteaToken string) *Manager {
	return &Manager{
		baseDir: baseDir,
		token:   giteaToken,
		repoMu:  make(map[string]*sync.Mutex),
	}
}

// WithAllowedOrigin pins HTTP(S) git clone/fetch/push operations and token transmission
// to the scheme and host of baseURL (e.g. "https://gitea.example.com").
func (m *Manager) WithAllowedOrigin(baseURL string) *Manager {
	if u, err := url.Parse(strings.TrimSpace(baseURL)); err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != "" {
		m.allowedOrigin = strings.ToLower(u.Scheme + "://" + u.Host)
	}
	return m
}

func (m *Manager) validateCloneOrigin(rawURL string) error {
	if m.allowedOrigin == "" {
		return nil
	}
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return fmt.Errorf("invalid clone URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil
	}
	origin := strings.ToLower(u.Scheme + "://" + u.Host)
	if origin != m.allowedOrigin {
		return fmt.Errorf("refusing untrusted clone URL origin %q (expected %q)", origin, m.allowedOrigin)
	}
	return nil
}

// CheckoutPR ensures the repo mirror is up to date and creates a temporary worktree at sha.
// The returned cleanup function removes the temporary worktree.
func (m *Manager) CheckoutPR(ctx context.Context, owner, repo, cloneURL, sha string) (worktreeDir string, cleanup func(), err error) {
	return m.checkoutPR(ctx, owner, repo, cloneURL, sha, false)
}

// CheckoutPRReadOnly creates a temporary worktree at sha without mutating an existing mirror
// via `git fetch` when the requested commit is already present locally (used by dry-run).
func (m *Manager) CheckoutPRReadOnly(ctx context.Context, owner, repo, cloneURL, sha string) (worktreeDir string, cleanup func(), err error) {
	return m.checkoutPR(ctx, owner, repo, cloneURL, sha, true)
}

func (m *Manager) checkoutPR(ctx context.Context, owner, repo, cloneURL, sha string, readOnly bool) (worktreeDir string, cleanup func(), err error) {
	if cloneURL == "" {
		return "", func() {}, fmt.Errorf("empty cloneURL for %s/%s", owner, repo)
	}
	if err := m.validateCloneOrigin(cloneURL); err != nil {
		return "", func() {}, err
	}
	lock := m.lockFor(owner + "/" + repo)
	lock.Lock()
	defer lock.Unlock()

	mirrorDir := filepath.Join(m.baseDir, "mirrors", sanitize(owner), sanitize(repo)+".git")
	if err := os.MkdirAll(filepath.Dir(mirrorDir), 0o755); err != nil {
		return "", func() {}, err
	}

	authArgs := gitAuthArgs(cloneURL, m.token)

	if _, statErr := os.Stat(mirrorDir); os.IsNotExist(statErr) {
		args := append(append([]string(nil), authArgs...), "clone", "--bare", cloneURL, mirrorDir)
		if err := m.runGit(ctx, "", args...); err != nil {
			return "", func() {}, fmt.Errorf("git clone --bare: %w", err)
		}
	} else {
		needFetch := true
		if readOnly && isValidCommitSHA(sha) {
			if _, revErr := m.runGitOutput(ctx, mirrorDir, 1024, "rev-parse", "--verify", sha+"^{commit}"); revErr == nil {
				needFetch = false
			}
		}
		if needFetch {
			args := append(append([]string(nil), authArgs...), "fetch", "--prune", cloneURL, "+refs/*:refs/*")
			if err := m.runGit(ctx, mirrorDir, args...); err != nil {
				return "", func() {}, fmt.Errorf("git fetch: %w", err)
			}
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
	if err := m.runGit(ctx, mirrorDir, "worktree", "add", "--detach", wtDir, target); err != nil {
		_ = os.RemoveAll(wtDir)
		return "", func() {}, fmt.Errorf("git worktree add: %w", err)
	}

	cleanupFn := func() {
		lock.Lock()
		defer lock.Unlock()
		_ = m.runGit(context.Background(), mirrorDir, "worktree", "remove", "--force", wtDir)
		_ = os.RemoveAll(wtDir)
	}
	return wtDir, cleanupFn, nil
}

// CommitAndPush stages all changes in worktreeDir, commits them, and pushes to headBranch on cloneURL.
func (m *Manager) CommitAndPush(ctx context.Context, worktreeDir, cloneURL, headBranch, authorName, commitMsg string) (string, error) {
	return m.CommitAndPushWithGuard(ctx, worktreeDir, cloneURL, headBranch, "", authorName, commitMsg)
}

// CommitAndPushWithGuard verifies origin pinning and optional expectedHeadSHA before pushing.
func (m *Manager) CommitAndPushWithGuard(ctx context.Context, worktreeDir, cloneURL, headBranch, expectedHeadSHA, authorName, commitMsg string) (string, error) {
	if worktreeDir == "" || cloneURL == "" || headBranch == "" {
		return "", fmt.Errorf("worktreeDir, cloneURL, and headBranch are required")
	}
	if err := m.validateCloneOrigin(cloneURL); err != nil {
		return "", err
	}
	if strings.HasPrefix(headBranch, "-") {
		return "", fmt.Errorf("invalid headBranch %q", headBranch)
	}
	if strings.TrimSpace(commitMsg) == "" {
		return "", fmt.Errorf("commit message is required")
	}
	if authorName == "" {
		authorName = "CodeSpider"
	}

	authArgs := gitAuthArgs(cloneURL, m.token)
	if expectedHeadSHA != "" {
		if !isValidCommitSHA(expectedHeadSHA) {
			return "", fmt.Errorf("invalid expectedHeadSHA %q", expectedHeadSHA)
		}
		lsArgs := append(append([]string(nil), authArgs...), "ls-remote", cloneURL, "refs/heads/"+headBranch)
		if lsOut, lsErr := m.runGitOutput(ctx, worktreeDir, 16*1024, lsArgs...); lsErr == nil {
			fields := strings.Fields(lsOut)
			if len(fields) > 0 && !strings.EqualFold(fields[0], expectedHeadSHA) {
				return "", fmt.Errorf("refusing push: remote branch %s moved from %s to %s", headBranch, expectedHeadSHA, fields[0])
			}
		}
	}

	if err := m.runGit(ctx, worktreeDir, "add", "-A"); err != nil {
		return "", fmt.Errorf("git add: %w", err)
	}

	statusOut, err := m.runGitOutput(ctx, worktreeDir, 256*1024, "status", "--porcelain")
	if err != nil {
		return "", fmt.Errorf("git status: %w", err)
	}
	if len(strings.TrimSpace(statusOut)) == 0 {
		return "", fmt.Errorf("no modified files to commit")
	}

	email := strings.ToLower(strings.ReplaceAll(authorName, " ", "")) + "@codespider.local"
	if err := m.runGit(ctx, worktreeDir,
		"-c", "user.name="+authorName,
		"-c", "user.email="+email,
		"commit", "-m", commitMsg,
	); err != nil {
		return "", fmt.Errorf("git commit: %w", err)
	}

	shaOut, err := m.runGitOutput(ctx, worktreeDir, 1024, "rev-parse", "HEAD")
	if err != nil {
		return "", fmt.Errorf("git rev-parse: %w", err)
	}
	newSHA := strings.TrimSpace(shaOut)

	refspec := fmt.Sprintf("HEAD:refs/heads/%s", headBranch)
	pushArgs := append(append([]string(nil), authArgs...), "push", "--atomic")
	if expectedHeadSHA != "" {
		pushArgs = append(pushArgs, "--force-with-lease=refs/heads/"+headBranch+":"+expectedHeadSHA)
	}
	pushArgs = append(pushArgs, cloneURL, refspec)
	if err := m.runGit(ctx, worktreeDir, pushArgs...); err != nil {
		return "", fmt.Errorf("git push: %w", err)
	}
	return newSHA, nil
}

// CleanupStaleWorktrees removes leftover temporary worktrees and prunes mirror metadata on startup.
func (m *Manager) CleanupStaleWorktrees(ctx context.Context) {
	wtBase := filepath.Join(m.baseDir, "worktrees")
	if entries, err := os.ReadDir(wtBase); err == nil {
		for _, entry := range entries {
			if ctx.Err() != nil {
				return
			}
			_ = os.RemoveAll(filepath.Join(wtBase, entry.Name()))
		}
	}

	mirrorsBase := filepath.Join(m.baseDir, "mirrors")
	_ = filepath.WalkDir(mirrorsBase, func(path string, d fs.DirEntry, err error) error {
		if err != nil || ctx.Err() != nil {
			return nil
		}
		if d.IsDir() && strings.HasSuffix(d.Name(), ".git") {
			_ = m.runGit(ctx, path, "worktree", "prune")
			return filepath.SkipDir
		}
		return nil
	})
}

// DiffCommits returns the unified diff between baseSHA and headSHA inside worktreeDir, capped at 5 MiB.
func (m *Manager) DiffCommits(ctx context.Context, worktreeDir, baseSHA, headSHA string) (string, error) {
	if worktreeDir == "" {
		return "", fmt.Errorf("worktreeDir is required")
	}
	if !isValidCommitSHA(baseSHA) || !isValidCommitSHA(headSHA) {
		return "", fmt.Errorf("invalid commit SHA range")
	}
	out, err := m.runGitOutput(ctx, worktreeDir, maxDiffBytes, "diff", "--no-ext-diff", "--unified=3", baseSHA+".."+headSHA, "--")
	if err != nil {
		return "", fmt.Errorf("git diff: %w", err)
	}
	return out, nil
}

// ListCachedMirrors returns sorted "owner/repo" slugs for all bare mirrors cached under baseDir.
func (m *Manager) ListCachedMirrors() []string {
	mirrorsBase := filepath.Join(m.baseDir, "mirrors")
	var repos []string
	_ = filepath.WalkDir(mirrorsBase, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() && strings.HasSuffix(d.Name(), ".git") {
			rel, relErr := filepath.Rel(mirrorsBase, path)
			if relErr == nil {
				slug := strings.TrimSuffix(filepath.ToSlash(rel), ".git")
				if strings.Contains(slug, "/") {
					repos = append(repos, slug)
				}
			}
			return filepath.SkipDir
		}
		return nil
	})
	sort.Strings(repos)
	return repos
}

// ReadMirrorFile reads a file from the cached bare mirror at ref (e.g. base branch) without trusting PR head.
func (m *Manager) ReadMirrorFile(ctx context.Context, owner, repo, ref, relPath string) ([]byte, error) {
	if owner == "" || repo == "" || ref == "" || relPath == "" {
		return nil, fmt.Errorf("owner, repo, ref, and relPath are required")
	}
	if strings.HasPrefix(ref, "-") || strings.HasPrefix(relPath, "-") || filepath.IsAbs(relPath) {
		return nil, fmt.Errorf("invalid ref or relPath")
	}
	cleanRel := filepath.ToSlash(filepath.Clean(relPath))
	if cleanRel == ".." || strings.HasPrefix(cleanRel, "../") {
		return nil, fmt.Errorf("path escapes repo: %s", relPath)
	}
	mirrorDir := filepath.Join(m.baseDir, "mirrors", sanitize(owner), sanitize(repo)+".git")
	if _, err := os.Stat(mirrorDir); err != nil {
		return nil, err
	}
	lock := m.lockFor(owner + "/" + repo)
	lock.Lock()
	defer lock.Unlock()

	for _, candidateRef := range []string{"refs/heads/" + ref, "refs/remotes/origin/" + ref, ref} {
		if out, err := m.runGitOutput(ctx, mirrorDir, 64*1024, "show", candidateRef+":"+cleanRel); err == nil {
			return []byte(out), nil
		}
	}
	return nil, os.ErrNotExist
}

// SearchCachedMirrors searches across other cached repository mirrors using `git grep` on HEAD
// to uncover cross-repository API/schema blast radius.
func (m *Manager) SearchCachedMirrors(ctx context.Context, excludeRepo, pattern string, maxMatches int) (string, error) {
	return m.SearchCachedMirrorsWithAllowlist(ctx, excludeRepo, pattern, nil, nil, maxMatches)
}

// SearchCachedMirrorsWithAllowlist searches cached mirrors restricted to allowedOwners and/or allowedRepos.
func (m *Manager) SearchCachedMirrorsWithAllowlist(ctx context.Context, excludeRepo, pattern string, allowedOwners, allowedRepos []string, maxMatches int) (string, error) {
	if strings.TrimSpace(pattern) == "" {
		return "", fmt.Errorf("pattern is required")
	}
	if _, err := regexp.Compile(pattern); err != nil {
		return "", fmt.Errorf("invalid regex %q: %w", pattern, err)
	}
	if maxMatches <= 0 {
		maxMatches = 40
	}

	ownerSet := make(map[string]bool, len(allowedOwners))
	for _, o := range allowedOwners {
		if o != "" {
			ownerSet[strings.ToLower(strings.TrimSpace(o))] = true
		}
	}
	repoSet := make(map[string]bool, len(allowedRepos))
	for _, r := range allowedRepos {
		if r != "" {
			repoSet[strings.ToLower(strings.TrimSpace(r))] = true
		}
	}

	mirrorsBase := filepath.Join(m.baseDir, "mirrors")
	repos := m.ListCachedMirrors()
	var targets []string
	for _, slug := range repos {
		if strings.EqualFold(slug, excludeRepo) {
			continue
		}
		if len(ownerSet) > 0 || len(repoSet) > 0 {
			owner, _, _ := strings.Cut(slug, "/")
			if !ownerSet[strings.ToLower(owner)] && !repoSet[strings.ToLower(slug)] {
				continue
			}
		}
		targets = append(targets, slug)
	}
	if len(targets) == 0 {
		return "no permitted cached repository mirrors available for cross-repo search", nil
	}

	var out strings.Builder
	total := 0
	for _, slug := range targets {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		mirrorDir := filepath.Join(mirrorsBase, filepath.FromSlash(slug)+".git")
		outStr, err := m.runGitOutput(ctx, mirrorDir, 512*1024, "grep", "-n", "-I", "-E", "-e", pattern, "HEAD")
		if err != nil {
			continue // No matches or unreadable ref in this mirror
		}

		for _, line := range strings.Split(strings.TrimSpace(outStr), "\n") {
			if line == "" {
				continue
			}
			cleaned := strings.TrimPrefix(line, "HEAD:")
			fmt.Fprintf(&out, "[%s] %s\n", slug, cleaned)
			total++
			if total >= maxMatches {
				return out.String(), nil
			}
		}
	}

	if total == 0 {
		return "no cross-repo matches found", nil
	}
	return out.String(), nil
}

var priorFixRe = regexp.MustCompile(`(?i)\b(fix|hotfix|security|cve|vuln|race|deadlock|revert|panic|leak)\b`)

// FileForensics inspects git commit history for relPath (optionally scoped to startLine..endLine)
// and highlights prior bugfix, security, or revert commits to prevent regressions.
func (m *Manager) FileForensics(ctx context.Context, worktreeDir, relPath string, startLine, endLine int) (string, error) {
	resolved, err := ResolveSafePath(worktreeDir, relPath)
	if err != nil {
		return "", err
	}
	evalRoot, err := filepath.Abs(worktreeDir)
	if err != nil {
		return "", err
	}
	if r, err := filepath.EvalSymlinks(evalRoot); err == nil {
		evalRoot = r
	}
	relClean, err := filepath.Rel(evalRoot, resolved)
	if err != nil {
		return "", err
	}
	relSlash := filepath.ToSlash(relClean)

	runLog := func(args ...string) (string, error) {
		return m.runGitOutput(ctx, evalRoot, 16*1024, args...)
	}

	var raw string
	if startLine > 0 && endLine >= startLine {
		locArg := fmt.Sprintf("%d,%d:%s", startLine, endLine, relSlash)
		raw, err = runLog("log", "-n", "8", "-s", "--date=short", "--pretty=format:%h %ad (%an) %s", "-L", locArg)
	}
	if err != nil || strings.TrimSpace(raw) == "" {
		raw, err = runLog("log", "-n", "10", "--date=short", "--pretty=format:%h %ad (%an) %s", "--", relSlash)
		if err != nil {
			return "", fmt.Errorf("git forensics: %w", err)
		}
	}
	if strings.TrimSpace(raw) == "" {
		return "no git history found for " + relSlash, nil
	}

	var out strings.Builder
	for _, line := range strings.Split(strings.TrimSpace(raw), "\n") {
		if line == "" {
			continue
		}
		if priorFixRe.MatchString(line) {
			out.WriteString("⚠️ [PRIOR FIX/REVERT] ")
		}
		out.WriteString(line)
		out.WriteByte('\n')
	}
	return out.String(), nil
}

// CommitPatches returns commit-by-commit patches between baseRef and headSHA (capped at 2 MiB)
// for scanning intermediate commits that may contain deleted secrets.
func (m *Manager) CommitPatches(ctx context.Context, worktreeDir, baseRef, headSHA string) (string, error) {
	if worktreeDir == "" || !isValidCommitSHA(headSHA) {
		return "", fmt.Errorf("worktreeDir and valid headSHA are required")
	}
	if baseRef == "" || strings.HasPrefix(baseRef, "-") {
		return "", fmt.Errorf("invalid baseRef")
	}

	baseSHA := ""
	for _, candidate := range []string{baseRef, "origin/" + baseRef, "refs/heads/" + baseRef} {
		if out, err := m.runGitOutput(ctx, worktreeDir, 1024, "rev-parse", "--verify", candidate); err == nil {
			sha := strings.TrimSpace(out)
			if isValidCommitSHA(sha) {
				baseSHA = sha
				break
			}
		}
	}
	if baseSHA == "" {
		return "", fmt.Errorf("could not resolve base ref %q", baseRef)
	}

	out, err := m.runGitOutput(ctx, worktreeDir, 2<<20, "log", "-p", "--no-ext-diff", "-n", "30", baseSHA+".."+headSHA, "--")
	if err != nil {
		return "", fmt.Errorf("git log -p: %w", err)
	}
	return out, nil
}

// ResolveSafePath resolves relPath inside rootDir and rejects absolute paths,
// lexical traversal, and symlinks pointing outside rootDir.
func ResolveSafePath(rootDir, relPath string) (string, error) {
	if strings.TrimSpace(rootDir) == "" {
		return "", fmt.Errorf("workspace root is required")
	}
	if filepath.IsAbs(relPath) || strings.HasPrefix(relPath, "/") || (runtime.GOOS == "windows" && (strings.HasPrefix(relPath, "\\") || filepath.VolumeName(relPath) != "")) {
		return "", fmt.Errorf("path must be relative: %s", relPath)
	}
	absRoot, err := filepath.Abs(rootDir)
	if err != nil {
		return "", err
	}
	evalRoot := absRoot
	if resolved, err := filepath.EvalSymlinks(absRoot); err == nil {
		evalRoot = resolved
	}

	joined := filepath.Clean(filepath.Join(evalRoot, relPath))
	if !isWithinRoot(evalRoot, joined) {
		return "", fmt.Errorf("path escapes workspace: %s", relPath)
	}

	curr := joined
	var tail []string
	for {
		_, lstatErr := os.Lstat(curr)
		if lstatErr == nil {
			break
		}
		if !os.IsNotExist(lstatErr) {
			return "", lstatErr
		}
		if curr == evalRoot {
			break
		}
		parent := filepath.Dir(curr)
		if parent == curr {
			break
		}
		tail = append(tail, filepath.Base(curr))
		curr = parent
	}

	evalCurr, err := filepath.EvalSymlinks(curr)
	if err != nil {
		return "", fmt.Errorf("path escapes workspace via symlink: %s", relPath)
	}

	finalPath := evalCurr
	for i := len(tail) - 1; i >= 0; i-- {
		finalPath = filepath.Join(finalPath, tail[i])
	}
	finalPath = filepath.Clean(finalPath)

	if !isWithinRoot(evalRoot, finalPath) {
		return "", fmt.Errorf("path escapes workspace via symlink: %s", relPath)
	}
	return finalPath, nil
}

func isWithinRoot(root, target string) bool {
	rel, err := filepath.Rel(root, target)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
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

// ReadSafeFile opens relPath inside rootDir without following a final symlink and bounds the read size.
func ReadSafeFile(rootDir, relPath string, maxBytes int64) ([]byte, error) {
	if maxBytes <= 0 {
		maxBytes = 2 << 20
	}
	full, err := ResolveSafePath(rootDir, relPath)
	if err != nil {
		return nil, err
	}
	if info, lErr := os.Lstat(full); lErr == nil && info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("refusing symlink read: %s", relPath)
	}
	f, err := openFileNoFollow(full, os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, maxBytes))
}

// WriteSafeFile writes data to relPath inside rootDir after verifying no symlink traversal or .git write.
func WriteSafeFile(rootDir, relPath string, data []byte) error {
	clean := filepath.ToSlash(filepath.Clean(relPath))
	if runtime.GOOS == "windows" {
		clean = strings.ToLower(clean)
	}
	if clean == ".git" || strings.HasPrefix(clean, ".git/") || strings.Contains(clean, "/.git/") {
		return fmt.Errorf("refusing to write inside .git: %s", relPath)
	}
	full, err := ResolveSafePath(rootDir, relPath)
	if err != nil {
		return err
	}
	if info, lErr := os.Lstat(full); lErr == nil && info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing symlink write: %s", relPath)
	}
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		return err
	}
	f, err := openFileNoFollow(full, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	_, writeErr := f.Write(data)
	closeErr := f.Close()
	if writeErr != nil {
		return writeErr
	}
	return closeErr
}

func (m *Manager) hardenedGitArgs(extraArgs ...string) []string {
	args := []string{
		"-c", "core.hooksPath=/dev/null",
		"-c", "core.fsmonitor=false",
		"-c", "submodule.recurse=false",
		"-c", "filter.lfs.smudge=",
		"-c", "filter.lfs.process=",
		"-c", "filter.lfs.clean=",
		"-c", "diff.external=",
	}
	if m.allowedOrigin != "" {
		args = append(args, "-c", "protocol.file.allow=never", "-c", "protocol.ext.allow=never")
	}
	return append(args, extraArgs...)
}

func (m *Manager) gitEnv() []string {
	return append(os.Environ(),
		"GIT_TERMINAL_PROMPT=0",
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_ATTR_NOSYSTEM=1",
	)
}

func (m *Manager) runGit(ctx context.Context, dir string, args ...string) error {
	cmd := exec.CommandContext(ctx, "git", m.hardenedGitArgs(args...)...)
	if dir != "" {
		cmd.Dir = dir
	}
	cmd.Env = m.gitEnv()
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := m.redact(strings.TrimSpace(string(out)))
		return fmt.Errorf("%w: %s", err, msg)
	}
	return nil
}

func (m *Manager) runGitOutput(ctx context.Context, dir string, maxStdout int, args ...string) (string, error) {
	if maxStdout <= 0 {
		maxStdout = 256 * 1024
	}
	cmd := exec.CommandContext(ctx, "git", m.hardenedGitArgs(args...)...)
	if dir != "" {
		cmd.Dir = dir
	}
	cmd.Env = m.gitEnv()
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &limitedWriter{buf: &stdout, max: maxStdout}
	cmd.Stderr = &limitedWriter{buf: &stderr, max: 32 * 1024}
	if err := cmd.Run(); err != nil {
		msg := m.redact(strings.TrimSpace(stderr.String()))
		return "", fmt.Errorf("%w: %s", err, msg)
	}
	return stdout.String(), nil
}

func (m *Manager) redact(s string) string {
	if m.token == "" {
		return s
	}
	basic := base64.StdEncoding.EncodeToString([]byte("oauth2:" + m.token))
	return redactSecrets(s, m.token, basic)
}

func redactSecrets(s string, secrets ...string) string {
	for _, sec := range secrets {
		if sec != "" {
			s = strings.ReplaceAll(s, sec, "[REDACTED]")
		}
	}
	return s
}

func gitAuthArgs(rawURL, token string) []string {
	if token == "" {
		return nil
	}
	u, err := url.Parse(rawURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return nil
	}
	basic := base64.StdEncoding.EncodeToString([]byte("oauth2:" + token))
	return []string{"-c", "http.extraHeader=Authorization: Basic " + basic}
}

func isValidCommitSHA(sha string) bool {
	if len(sha) < 7 || len(sha) > 64 {
		return false
	}
	for i := 0; i < len(sha); i++ {
		c := sha[i]
		isHex := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
		if !isHex {
			return false
		}
	}
	return true
}

func sanitize(s string) string {
	s = strings.ReplaceAll(s, "..", "_")
	s = strings.ReplaceAll(s, "/", "_")
	s = strings.ReplaceAll(s, "\\", "_")
	s = strings.ReplaceAll(s, ":", "_")
	return s
}

type limitedWriter struct {
	buf *bytes.Buffer
	max int
}

func (w *limitedWriter) Write(p []byte) (int, error) {
	rem := w.max - w.buf.Len()
	if rem > 0 {
		if len(p) > rem {
			w.buf.Write(p[:rem])
		} else {
			w.buf.Write(p)
		}
	}
	return len(p), nil
}
