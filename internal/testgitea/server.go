// Package testgitea provides a stateful local Gitea + real Git Smart-HTTP test server
// backed by disposable bare git repositories for end-to-end integration testing.
package testgitea

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cgi"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/Eresus-Security-OSS/CodeSpider/internal/gitea"
)

// Server is a stateful fake Gitea v1 API + real Git Smart-HTTP CGI server.
type Server struct {
	URL           string
	Token         string
	WebhookSecret string
	HTTP          *httptest.Server

	reposDir       string
	gitHTTPBackend string

	mu            sync.Mutex
	nextID        int64
	Collaborators map[string]bool // "owner/repo/user" -> true
	PRs           map[string]*gitea.PullRequest
	Reviews       map[string][]gitea.CreateReviewRequest
	Comments      map[string][]gitea.Comment
	Statuses      map[string][]string
}

// NewServer starts an isolated local Gitea + Git Smart-HTTP server.
func NewServer(t *testing.T, token, webhookSecret string) *Server {
	t.Helper()
	execPathOut, err := exec.Command("git", "--exec-path").Output()
	if err != nil {
		t.Skipf("git --exec-path failed: %v", err)
	}
	backend := filepath.Join(strings.TrimSpace(string(execPathOut)), "git-http-backend")
	if _, err := os.Stat(backend); err != nil {
		t.Skipf("git-http-backend not found at %s: %v", backend, err)
	}

	s := &Server{
		Token:          token,
		WebhookSecret:  webhookSecret,
		reposDir:       t.TempDir(),
		gitHTTPBackend: backend,
		nextID:         1,
		Collaborators:  make(map[string]bool),
		PRs:            make(map[string]*gitea.PullRequest),
		Reviews:        make(map[string][]gitea.CreateReviewRequest),
		Comments:       make(map[string][]gitea.Comment),
		Statuses:       make(map[string][]string),
	}
	s.HTTP = httptest.NewServer(s)
	s.URL = s.HTTP.URL
	t.Cleanup(s.HTTP.Close)
	return s
}

// InitRepo creates a bare git repository with an initial commit on main and returns its HTTP clone URL.
func (s *Server) InitRepo(t *testing.T, owner, repo string, baseFiles map[string]string) string {
	t.Helper()
	bareDir := filepath.Join(s.reposDir, owner, repo+".git")
	if err := os.MkdirAll(filepath.Dir(bareDir), 0o755); err != nil {
		t.Fatal(err)
	}
	runGit(t, "", "init", "--bare", bareDir)
	runGit(t, bareDir, "config", "http.receivepack", "true")

	work := t.TempDir()
	runGit(t, work, "init", "-b", "main")
	writeFiles(t, work, baseFiles)
	runGit(t, work, "add", ".")
	runGit(t, work, "commit", "-m", "initial commit")
	runGit(t, work, "push", bareDir, "HEAD:refs/heads/main")
	runGit(t, bareDir, "symbolic-ref", "HEAD", "refs/heads/main")

	return s.URL + "/git/" + owner + "/" + repo + ".git"
}

// CreatePR pushes one or more sequential commits onto branch and registers a PullRequest.
func (s *Server) CreatePR(t *testing.T, owner, repo, branch, title, body, author string, isFork bool, commits []map[string]string) gitea.PullRequest {
	t.Helper()
	bareDir := filepath.Join(s.reposDir, owner, repo+".git")
	work := t.TempDir()
	runGit(t, "", "clone", bareDir, work)
	runGit(t, work, "checkout", "-b", branch)

	for i, files := range commits {
		writeFiles(t, work, files)
		runGit(t, work, "add", ".")
		runGit(t, work, "commit", "-m", fmt.Sprintf("pr commit %d", i+1))
	}
	runGit(t, work, "push", bareDir, "HEAD:refs/heads/"+branch)
	headSHA := runGit(t, work, "rev-parse", "HEAD")

	cloneURL := s.URL + "/git/" + owner + "/" + repo + ".git"
	headRepo := gitea.Repository{ID: 1, FullName: owner + "/" + repo, CloneURL: cloneURL}
	if isFork {
		headRepo = gitea.Repository{ID: 999, FullName: author + "/" + repo, CloneURL: cloneURL}
	}

	s.mu.Lock()
	num := s.nextID
	s.nextID++
	pr := gitea.PullRequest{
		Number: num,
		State:  "open",
		Title:  title,
		Body:   body,
		User:   gitea.User{Username: author},
		Base:   gitea.BranchRef{Ref: "main", Repo: gitea.Repository{ID: 1, FullName: owner + "/" + repo, CloneURL: cloneURL}},
		Head:   gitea.BranchRef{Ref: branch, SHA: headSHA, Repo: headRepo},
	}
	s.PRs[fmt.Sprintf("%s/%s#%d", owner, repo, num)] = &pr
	s.mu.Unlock()
	return pr
}

// AdvancePRHead pushes a new commit to an existing PR to simulate a race condition.
func (s *Server) AdvancePRHead(t *testing.T, owner, repo string, prNumber int64, files map[string]string) string {
	t.Helper()
	key := fmt.Sprintf("%s/%s#%d", owner, repo, prNumber)
	s.mu.Lock()
	pr := s.PRs[key]
	s.mu.Unlock()

	bareDir := filepath.Join(s.reposDir, owner, repo+".git")
	work := t.TempDir()
	runGit(t, "", "clone", "-b", pr.Head.Ref, bareDir, work)
	writeFiles(t, work, files)
	runGit(t, work, "add", ".")
	runGit(t, work, "commit", "-m", "advance head")
	runGit(t, work, "push", bareDir, "HEAD:refs/heads/"+pr.Head.Ref)
	newSHA := runGit(t, work, "rev-parse", "HEAD")

	s.mu.Lock()
	pr.Head.SHA = newSHA
	s.mu.Unlock()
	return newSHA
}

// SignPayload computes a Gitea X-Gitea-Signature HMAC-SHA256 hex digest.
func (s *Server) SignPayload(payload []byte) string {
	mac := hmac.New(sha256.New, []byte(s.WebhookSecret))
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/git/") {
		if s.Token != "" {
			want := "Basic " + base64.StdEncoding.EncodeToString([]byte("oauth2:"+s.Token))
			if r.Header.Get("Authorization") != want {
				http.Error(w, "unauthorized git", http.StatusUnauthorized)
				return
			}
		}
		origPath := r.URL.Path
		r2 := r.Clone(r.Context())
		r2.URL.Path = strings.TrimPrefix(origPath, "/git")
		h := &cgi.Handler{
			Path: s.gitHTTPBackend,
			Dir:  s.reposDir,
			Env: []string{
				"GIT_PROJECT_ROOT=" + s.reposDir,
				"GIT_HTTP_EXPORT_ALL=1",
				"PATH_INFO=" + r2.URL.Path,
			},
		}
		h.ServeHTTP(w, r2)
		return
	}

	if s.Token != "" && r.Header.Get("Authorization") != "token "+s.Token {
		http.Error(w, "unauthorized api", http.StatusUnauthorized)
		return
	}

	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	// /api/v1/repos/{owner}/{repo}/...
	if len(parts) < 6 || parts[0] != "api" || parts[1] != "v1" || parts[2] != "repos" {
		http.NotFound(w, r)
		return
	}
	owner, repo := parts[3], parts[4]
	rest := parts[5:]

	w.Header().Set("Content-Type", "application/json")
	switch {
	case len(rest) == 2 && rest[0] == "pulls" && strings.HasSuffix(rest[1], ".diff"):
		numStr := strings.TrimSuffix(rest[1], ".diff")
		key := fmt.Sprintf("%s/%s#%s", owner, repo, numStr)
		s.mu.Lock()
		pr := s.PRs[key]
		s.mu.Unlock()
		if pr == nil {
			http.NotFound(w, r)
			return
		}
		bareDir := filepath.Join(s.reposDir, owner, repo+".git")
		cmd := exec.Command("git", "diff", "refs/heads/"+pr.Base.Ref+".."+pr.Head.SHA)
		cmd.Dir = bareDir
		diffOut, _ := cmd.Output()
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write(diffOut)

	case len(rest) == 2 && rest[0] == "pulls" && r.Method == http.MethodGet:
		key := fmt.Sprintf("%s/%s#%s", owner, repo, rest[1])
		s.mu.Lock()
		pr := s.PRs[key]
		s.mu.Unlock()
		if pr == nil {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(pr)

	case len(rest) == 3 && rest[0] == "pulls" && rest[2] == "reviews":
		key := fmt.Sprintf("%s/%s#%s", owner, repo, rest[1])
		if r.Method == http.MethodPost {
			var rev gitea.CreateReviewRequest
			_ = json.NewDecoder(r.Body).Decode(&rev)
			s.mu.Lock()
			s.Reviews[key] = append(s.Reviews[key], rev)
			s.mu.Unlock()
			w.WriteHeader(http.StatusOK)
			return
		}
		s.mu.Lock()
		revs := s.Reviews[key]
		s.mu.Unlock()
		_ = json.NewEncoder(w).Encode(revs)

	case len(rest) == 3 && rest[0] == "issues" && rest[2] == "comments":
		key := fmt.Sprintf("%s/%s#%s", owner, repo, rest[1])
		if r.Method == http.MethodPost {
			var body struct {
				Body string `json:"body"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			s.mu.Lock()
			id := s.nextID
			s.nextID++
			s.Comments[key] = append(s.Comments[key], gitea.Comment{ID: id, Body: body.Body})
			s.mu.Unlock()
			w.WriteHeader(http.StatusCreated)
			return
		}
		s.mu.Lock()
		cms := s.Comments[key]
		s.mu.Unlock()
		_ = json.NewEncoder(w).Encode(cms)

	case len(rest) == 3 && rest[0] == "issues" && rest[1] == "comments" && r.Method == http.MethodPatch:
		id, _ := strconv.ParseInt(rest[2], 10, 64)
		var body struct {
			Body string `json:"body"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		s.mu.Lock()
		for k, list := range s.Comments {
			for i := range list {
				if list[i].ID == id {
					s.Comments[k][i].Body = body.Body
				}
			}
		}
		s.mu.Unlock()
		w.WriteHeader(http.StatusOK)

	case len(rest) == 2 && rest[0] == "collaborators":
		s.mu.Lock()
		ok := s.Collaborators[owner+"/"+repo+"/"+rest[1]]
		s.mu.Unlock()
		if ok {
			w.WriteHeader(http.StatusNoContent)
		} else {
			w.WriteHeader(http.StatusNotFound)
		}

	case len(rest) == 2 && rest[0] == "statuses":
		var st struct {
			State       string `json:"state"`
			Description string `json:"description"`
		}
		_ = json.NewDecoder(r.Body).Decode(&st)
		s.mu.Lock()
		s.Statuses[rest[1]] = append(s.Statuses[rest[1]], st.State)
		s.mu.Unlock()
		w.WriteHeader(http.StatusCreated)

	default:
		w.WriteHeader(http.StatusOK)
	}
}

func runGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	if dir != "" {
		cmd.Dir = dir
	}
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=Tester",
		"GIT_AUTHOR_EMAIL=tester@example.com",
		"GIT_COMMITTER_NAME=Tester",
		"GIT_COMMITTER_EMAIL=tester@example.com",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v failed: %v\n%s", args, err, string(out))
	}
	return strings.TrimSpace(string(out))
}

func writeFiles(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for rel, content := range files {
		full := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}
