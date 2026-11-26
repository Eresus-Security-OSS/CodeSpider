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

// CreateReview submits a PR review with a summary body and optional inline comments.
func (c *Client) CreateReview(ctx context.Context, owner, repo string, number int64, review CreateReviewRequest) error {
	if review.Event == "" {
		review.Event = "COMMENT"
	}
	path := fmt.Sprintf("/api/v1/repos/%s/%s/pulls/%d/reviews", url.PathEscape(owner), url.PathEscape(repo), number)
	return c.doJSON(ctx, http.MethodPost, path, review, nil)
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
