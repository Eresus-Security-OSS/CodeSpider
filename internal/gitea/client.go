package gitea

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client interacts with the Gitea v1 REST API.
type Client struct {
	baseURL    string
	token      string
	httpClient *http.Client
}

// NewClient creates a new Gitea REST API client.
func NewClient(baseURL, token string) *Client {
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		token:   token,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// GetPullRequest fetches metadata for a pull request.
func (c *Client) GetPullRequest(ctx context.Context, owner, repo string, number int64) (PullRequest, error) {
	path := fmt.Sprintf("/api/v1/repos/%s/%s/pulls/%d", url.PathEscape(owner), url.PathEscape(repo), number)
	var pr PullRequest
	if err := c.doJSON(ctx, http.MethodGet, path, nil, &pr); err != nil {
		return PullRequest{}, err
	}
	return pr, nil
}

// ListOpenPullRequests lists open pull requests for a repository.
func (c *Client) ListOpenPullRequests(ctx context.Context, owner, repo string) ([]PullRequest, error) {
	path := fmt.Sprintf("/api/v1/repos/%s/%s/pulls?state=open&limit=50", url.PathEscape(owner), url.PathEscape(repo))
	var prs []PullRequest
	if err := c.doJSON(ctx, http.MethodGet, path, nil, &prs); err != nil {
		return nil, err
	}
	return prs, nil
}

// GetPullRequestDiff fetches the raw unified diff of a pull request.
func (c *Client) GetPullRequestDiff(ctx context.Context, owner, repo string, number int64) (string, error) {
	path := fmt.Sprintf("/api/v1/repos/%s/%s/pulls/%d.diff", url.PathEscape(owner), url.PathEscape(repo), number)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return "", err
	}
	c.setAuth(req)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 5<<20))
	if err != nil {
		return "", err
	}
	if resp.StatusCode >= 300 {
		return "", fmt.Errorf("gitea diff %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	return string(body), nil
}

// ListPRComments lists issue/PR conversation comments.
func (c *Client) ListPRComments(ctx context.Context, owner, repo string, number int64) ([]Comment, error) {
	path := fmt.Sprintf("/api/v1/repos/%s/%s/issues/%d/comments", url.PathEscape(owner), url.PathEscape(repo), number)
	var comments []Comment
	if err := c.doJSON(ctx, http.MethodGet, path, nil, &comments); err != nil {
		return nil, err
	}
	return comments, nil
}

// PostComment posts a top-level comment on a pull request.
func (c *Client) PostComment(ctx context.Context, owner, repo string, number int64, body string) error {
	path := fmt.Sprintf("/api/v1/repos/%s/%s/issues/%d/comments", url.PathEscape(owner), url.PathEscape(repo), number)
	payload := map[string]string{"body": body}
	return c.doJSON(ctx, http.MethodPost, path, payload, nil)
}

// EditComment updates an existing issue/PR comment by ID.
func (c *Client) EditComment(ctx context.Context, owner, repo string, commentID int64, body string) error {
	path := fmt.Sprintf("/api/v1/repos/%s/%s/issues/comments/%d", url.PathEscape(owner), url.PathEscape(repo), commentID)
	return c.doJSON(ctx, http.MethodPatch, path, map[string]string{"body": body}, nil)
}

// UpsertStickyComment updates an existing comment containing marker or posts a new one.
func (c *Client) UpsertStickyComment(ctx context.Context, owner, repo string, prNumber int64, marker, body string) error {
	if !strings.Contains(body, marker) {
		body = marker + "\n" + body
	}
	comments, err := c.ListPRComments(ctx, owner, repo, prNumber)
	if err == nil {
		for _, cm := range comments {
			if strings.Contains(cm.Body, marker) {
				return c.EditComment(ctx, owner, repo, cm.ID, body)
			}
		}
	}
	return c.PostComment(ctx, owner, repo, prNumber, body)
}

// IsCollaborator checks whether username is the repo owner or a collaborator with write/admin access.
func (c *Client) IsCollaborator(ctx context.Context, owner, repo, username string) (bool, error) {
	if username == "" {
		return false, nil
	}
	if strings.EqualFold(owner, username) {
		return true, nil
	}
	path := fmt.Sprintf("/api/v1/repos/%s/%s/collaborators/%s", url.PathEscape(owner), url.PathEscape(repo), url.PathEscape(username))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return false, err
	}
	c.setAuth(req)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	_, _ = io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusOK {
		return true, nil
	}
	if resp.StatusCode == http.StatusNotFound {
		return false, nil
	}
	return false, fmt.Errorf("gitea collaborator check %s", resp.Status)
}

// EnsureAndAddLabels creates missing repository labels and attaches them to the PR.
func (c *Client) EnsureAndAddLabels(ctx context.Context, owner, repo string, prNumber int64, names []string) error {
	if len(names) == 0 {
		return nil
	}
	listPath := fmt.Sprintf("/api/v1/repos/%s/%s/labels?limit=100", url.PathEscape(owner), url.PathEscape(repo))
	var existing []Label
	if err := c.doJSON(ctx, http.MethodGet, listPath, nil, &existing); err != nil {
		return err
	}
	byName := make(map[string]int64, len(existing))
	for _, lbl := range existing {
		byName[strings.ToLower(lbl.Name)] = lbl.ID
	}

	var ids []int64
	createPath := fmt.Sprintf("/api/v1/repos/%s/%s/labels", url.PathEscape(owner), url.PathEscape(repo))
	for _, name := range names {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if id, ok := byName[strings.ToLower(name)]; ok {
			ids = append(ids, id)
			continue
		}
		var created Label
		if err := c.doJSON(ctx, http.MethodPost, createPath, map[string]string{
			"name":  name,
			"color": labelColor(name),
		}, &created); err != nil {
			continue
		}
		if created.ID > 0 {
			ids = append(ids, created.ID)
			byName[strings.ToLower(name)] = created.ID
		}
	}
	if len(ids) == 0 {
		return nil
	}
	attachPath := fmt.Sprintf("/api/v1/repos/%s/%s/issues/%d/labels", url.PathEscape(owner), url.PathEscape(repo), prNumber)
	return c.doJSON(ctx, http.MethodPost, attachPath, map[string][]int64{"labels": ids}, nil)
}

func labelColor(name string) string {
	switch {
	case strings.EqualFold(name, "security"):
		return "#d73a4a"
	case strings.EqualFold(name, "tests"):
		return "#0e8a16"
	case strings.HasPrefix(strings.ToLower(name), "size/"):
		return "#5319e7"
	default:
		return "#0075ca"
	}
}

// RequestReviewers requests Gitea PR reviews from the specified usernames.
func (c *Client) RequestReviewers(ctx context.Context, owner, repo string, prNumber int64, reviewers []string) error {
	if len(reviewers) == 0 {
		return nil
	}
	path := fmt.Sprintf("/api/v1/repos/%s/%s/pulls/%d/requested_reviewers", url.PathEscape(owner), url.PathEscape(repo), prNumber)
	return c.doJSON(ctx, http.MethodPost, path, map[string][]string{"reviewers": reviewers}, nil)
}

// GetCombinedCommitStatus fetches CI/commit status checks for ref.
func (c *Client) GetCombinedCommitStatus(ctx context.Context, owner, repo, ref string) (CombinedStatus, error) {
	path := fmt.Sprintf("/api/v1/repos/%s/%s/commits/%s/status", url.PathEscape(owner), url.PathEscape(repo), url.PathEscape(ref))
	var st CombinedStatus
	if err := c.doJSON(ctx, http.MethodGet, path, nil, &st); err != nil {
		return CombinedStatus{}, err
	}
	return st, nil
}

// CreateReview submits a PR review with a summary body and optional inline comments.
func (c *Client) CreateReview(ctx context.Context, owner, repo string, number int64, review CreateReviewRequest) error {
	if review.Event == "" {
		review.Event = "COMMENT"
	}
	path := fmt.Sprintf("/api/v1/repos/%s/%s/pulls/%d/reviews", url.PathEscape(owner), url.PathEscape(repo), number)
	return c.doJSON(ctx, http.MethodPost, path, review, nil)
}

// ListPullReviews fetches existing reviews submitted on a pull request.
func (c *Client) ListPullReviews(ctx context.Context, owner, repo string, number int64) ([]PullReview, error) {
	path := fmt.Sprintf("/api/v1/repos/%s/%s/pulls/%d/reviews", url.PathEscape(owner), url.PathEscape(repo), number)
	var reviews []PullReview
	if err := c.doJSON(ctx, http.MethodGet, path, nil, &reviews); err != nil {
		return nil, err
	}
	return reviews, nil
}

// AddIssueReaction adds an emoji reaction (e.g., "eyes") to an issue or pull request.
func (c *Client) AddIssueReaction(ctx context.Context, owner, repo string, issueNumber int64, content string) error {
	path := fmt.Sprintf("/api/v1/repos/%s/%s/issues/%d/reactions", url.PathEscape(owner), url.PathEscape(repo), issueNumber)
	return c.doJSON(ctx, http.MethodPost, path, map[string]string{"content": content}, nil)
}

// AddCommentReaction adds an emoji reaction (e.g., "eyes") to an issue/PR comment.
func (c *Client) AddCommentReaction(ctx context.Context, owner, repo string, commentID int64, content string) error {
	path := fmt.Sprintf("/api/v1/repos/%s/%s/issues/comments/%d/reactions", url.PathEscape(owner), url.PathEscape(repo), commentID)
	return c.doJSON(ctx, http.MethodPost, path, map[string]string{"content": content}, nil)
}

// ListAccessibleRepos lists repositories accessible to the authenticated bot user (up to 250).
func (c *Client) ListAccessibleRepos(ctx context.Context) ([]Repository, error) {
	var all []Repository
	for page := 1; page <= 5; page++ {
		path := fmt.Sprintf("/api/v1/user/repos?limit=50&page=%d", page)
		var batch []Repository
		if err := c.doJSON(ctx, http.MethodGet, path, nil, &batch); err != nil {
			return nil, err
		}
		all = append(all, batch...)
		if len(batch) < 50 {
			break
		}
	}
	return all, nil
}

// SetCommitStatus sets a commit status (pending, success, error, failure) on a SHA.
func (c *Client) SetCommitStatus(ctx context.Context, owner, repo, sha, state, description string) error {
	if sha == "" {
		return nil
	}
	path := fmt.Sprintf("/api/v1/repos/%s/%s/statuses/%s", url.PathEscape(owner), url.PathEscape(repo), url.PathEscape(sha))
	payload := map[string]string{
		"state":       state,
		"description": description,
		"context":     "codespider/review",
	}
	return c.doJSON(ctx, http.MethodPost, path, payload, nil)
}

func (c *Client) doJSON(ctx context.Context, method, path string, in any, out any) error {
	var bodyReader io.Reader
	if in != nil {
		raw, err := json.Marshal(in)
		if err != nil {
			return err
		}
		bodyReader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bodyReader)
	if err != nil {
		return err
	}
	c.setAuth(req)
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 5<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 300 {
		return fmt.Errorf("gitea %s %s: %s: %s", method, path, resp.Status, strings.TrimSpace(string(respBody)))
	}
	if out != nil && len(respBody) > 0 {
		if err := json.Unmarshal(respBody, out); err != nil {
			return fmt.Errorf("decode gitea response: %w", err)
		}
	}
	return nil
}

func (c *Client) setAuth(req *http.Request) {
	if c.token != "" {
		req.Header.Set("Authorization", "token "+c.token)
	}
}
