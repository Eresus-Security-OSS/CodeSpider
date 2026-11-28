// Package github implements the ForgeProvider contract using GitHub's REST API.
package github

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Eresus-Security-OSS/CodeSpider/internal/gitea"
	forgeprovider "github.com/Eresus-Security-OSS/CodeSpider/internal/provider"
)

var _ forgeprovider.ForgeProvider = (*Client)(nil)
var _ forgeprovider.ReviewThreadResolver = (*Client)(nil)

// Client calls the GitHub REST API. baseURL supports GitHub Enterprise; use
// https://api.github.com for GitHub.com.
type Client struct {
	baseURL          string
	token            string
	tokenSource      TokenSource
	installationAuth bool
	httpClient       *http.Client
	threadMu         sync.Mutex
	threadIDs        map[int64]string
}

func NewClient(baseURL, token string) *Client {
	if baseURL == "" {
		baseURL = "https://api.github.com"
	}
	return &Client{baseURL: strings.TrimRight(baseURL, "/"), token: token, httpClient: &http.Client{Timeout: 30 * time.Second}, threadIDs: make(map[int64]string)}
}

func NewClientWithTokenSource(baseURL string, source TokenSource) *Client {
	c := NewClient(baseURL, "")
	c.tokenSource = source
	c.installationAuth = true
	return c
}

func (c *Client) Name() string { return "github" }

type repository struct {
	ID       int64  `json:"id"`
	FullName string `json:"full_name"`
	CloneURL string `json:"clone_url"`
}
type user struct {
	Login string `json:"login"`
	Type  string `json:"type"`
}
type branch struct {
	Label string      `json:"label"`
	Ref   string      `json:"ref"`
	SHA   string      `json:"sha"`
	Repo  *repository `json:"repo"`
}
type pullRequest struct {
	Number  int64  `json:"number"`
	State   string `json:"state"`
	Title   string `json:"title"`
	Body    string `json:"body"`
	Draft   bool   `json:"draft"`
	HTMLURL string `json:"html_url"`
	DiffURL string `json:"diff_url"`
	Head    branch `json:"head"`
	Base    branch `json:"base"`
	User    user   `json:"user"`
	Merged  bool   `json:"merged"`
}

func mapPullRequest(p pullRequest) gitea.PullRequest {
	out := gitea.PullRequest{Number: p.Number, State: p.State, Title: p.Title, Body: p.Body, Draft: p.Draft, HTMLURL: p.HTMLURL, DiffURL: p.DiffURL, Merged: p.Merged, User: gitea.User{Login: p.User.Login, Type: p.User.Type}, Head: gitea.BranchRef{Label: p.Head.Label, Ref: p.Head.Ref, SHA: p.Head.SHA}, Base: gitea.BranchRef{Label: p.Base.Label, Ref: p.Base.Ref, SHA: p.Base.SHA}}
	if p.Head.Repo != nil {
		out.Head.Repo = mapRepo(*p.Head.Repo)
	}
	if p.Base.Repo != nil {
		out.Base.Repo = mapRepo(*p.Base.Repo)
	}
	return out
}

func mapRepo(r repository) gitea.Repository {
	return gitea.Repository{ID: r.ID, FullName: r.FullName, CloneURL: r.CloneURL}
}

func (c *Client) GetPullRequest(ctx context.Context, owner, repo string, number int64) (gitea.PullRequest, error) {
	var p pullRequest
	if err := c.request(ctx, http.MethodGet, fmt.Sprintf("/repos/%s/%s/pulls/%d", esc(owner), esc(repo), number), nil, &p, "application/vnd.github+json"); err != nil {
		return gitea.PullRequest{}, err
	}
	return mapPullRequest(p), nil
}

func (c *Client) ListOpenPullRequests(ctx context.Context, owner, repo string) ([]gitea.PullRequest, error) {
	out := make([]gitea.PullRequest, 0)
	for page := 1; page <= 10; page++ {
		var prs []pullRequest
		path := fmt.Sprintf("/repos/%s/%s/pulls?state=open&per_page=100&page=%d", esc(owner), esc(repo), page)
		if err := c.request(ctx, http.MethodGet, path, nil, &prs, "application/vnd.github+json"); err != nil {
			return nil, err
		}
		for _, pr := range prs {
			out = append(out, mapPullRequest(pr))
		}
		if len(prs) < 100 {
			break
		}
	}
	return out, nil
}

func (c *Client) ListAccessibleRepos(ctx context.Context) ([]gitea.Repository, error) {
	const pageSize, maxPages = 100, 10
	out := make([]gitea.Repository, 0)
	for page := 1; page <= maxPages; page++ {
		path := fmt.Sprintf("/user/repos?per_page=%d&page=%d", pageSize, page)
		var repos []repository
		if c.installationAuth {
			var response struct {
				Repositories []repository `json:"repositories"`
			}
			path = fmt.Sprintf("/installation/repositories?per_page=%d&page=%d", pageSize, page)
			if err := c.request(ctx, http.MethodGet, path, nil, &response, "application/vnd.github+json"); err != nil {
				return nil, err
			}
			repos = response.Repositories
		} else if err := c.request(ctx, http.MethodGet, path, nil, &repos, "application/vnd.github+json"); err != nil {
			return nil, err
		}
		for _, repo := range repos {
			out = append(out, gitea.Repository{ID: repo.ID, FullName: repo.FullName, CloneURL: repo.CloneURL})
		}
		if len(repos) < pageSize {
			break
		}
	}
	return out, nil
}

func (c *Client) GetPullRequestDiff(ctx context.Context, owner, repo string, number int64) (string, error) {
	var body string
	if err := c.request(ctx, http.MethodGet, fmt.Sprintf("/repos/%s/%s/pulls/%d", esc(owner), esc(repo), number), nil, &body, "application/vnd.github.diff"); err != nil {
		return "", err
	}
	return body, nil
}

func (c *Client) SubmitReview(ctx context.Context, owner, repo string, number int64, review gitea.CreateReviewRequest) error {
	type comment struct {
		Path string `json:"path"`
		Body string `json:"body"`
		Line int64  `json:"line,omitempty"`
		Side string `json:"side,omitempty"`
	}
	payload := struct {
		CommitID string    `json:"commit_id,omitempty"`
		Body     string    `json:"body"`
		Event    string    `json:"event"`
		Comments []comment `json:"comments,omitempty"`
	}{CommitID: review.CommitID, Body: review.Body, Event: review.Event}
	if payload.Event == "" {
		payload.Event = "COMMENT"
	}
	for _, cm := range review.Comments {
		line, side := cm.NewLineNum, "RIGHT"
		if line == 0 {
			line, side = cm.OldLineNum, "LEFT"
		}
		if line == 0 {
			return fmt.Errorf("github review comment for %q has no line", cm.Path)
		}
		payload.Comments = append(payload.Comments, comment{Path: cm.Path, Body: cm.Body, Line: line, Side: side})
	}
	return c.request(ctx, http.MethodPost, fmt.Sprintf("/repos/%s/%s/pulls/%d/reviews", esc(owner), esc(repo), number), payload, nil, "application/vnd.github+json")
}

func (c *Client) PostComment(ctx context.Context, owner, repo string, number int64, body string) error {
	return c.request(ctx, http.MethodPost, fmt.Sprintf("/repos/%s/%s/issues/%d/comments", esc(owner), esc(repo), number), map[string]string{"body": body}, nil, "application/vnd.github+json")
}

func (c *Client) ListPRComments(ctx context.Context, owner, repo string, number int64) ([]gitea.Comment, error) {
	type commentRecord struct {
		ID        int64     `json:"id"`
		Body      string    `json:"body"`
		HTMLURL   string    `json:"html_url"`
		CreatedAt time.Time `json:"created_at"`
		User      user      `json:"user"`
	}
	var all []gitea.Comment
	for page := 1; page <= 20; page++ {
		var batch []commentRecord
		path := fmt.Sprintf("/repos/%s/%s/issues/%d/comments?per_page=100&page=%d", esc(owner), esc(repo), number, page)
		if err := c.request(ctx, http.MethodGet, path, nil, &batch, "application/vnd.github+json"); err != nil {
			return nil, err
		}
		for _, cm := range batch {
			all = append(all, gitea.Comment{ID: cm.ID, Body: cm.Body, HTMLURL: cm.HTMLURL, CreatedAt: cm.CreatedAt, User: gitea.User{Login: cm.User.Login, Type: cm.User.Type}})
		}
		if len(batch) < 100 {
			break
		}
	}
	return all, nil
}

func (c *Client) ListPullReviews(ctx context.Context, owner, repo string, number int64) ([]gitea.PullReview, error) {
	type reviewRecord struct {
		ID          int64     `json:"id"`
		State       string    `json:"state"`
		Body        string    `json:"body"`
		CommitID    string    `json:"commit_id"`
		SubmittedAt time.Time `json:"submitted_at"`
		User        user      `json:"user"`
	}
	var all []gitea.PullReview
	for page := 1; page <= 20; page++ {
		var batch []reviewRecord
		path := fmt.Sprintf("/repos/%s/%s/pulls/%d/reviews?per_page=100&page=%d", esc(owner), esc(repo), number, page)
		if err := c.request(ctx, http.MethodGet, path, nil, &batch, "application/vnd.github+json"); err != nil {
			return nil, err
		}
		for _, rv := range batch {
			all = append(all, gitea.PullReview{ID: rv.ID, State: rv.State, Body: rv.Body, CommitID: rv.CommitID, SubmittedAt: rv.SubmittedAt, User: gitea.User{Login: rv.User.Login, Type: rv.User.Type}})
		}
		if len(batch) < 100 {
			break
		}
	}
	return all, nil
}

func (c *Client) GetCombinedCommitStatus(ctx context.Context, owner, repo, ref string) (gitea.CombinedStatus, error) {
	type statusRecord struct {
		State       string `json:"state"`
		Context     string `json:"context"`
		Description string `json:"description"`
	}
	var response struct {
		State    string         `json:"state"`
		Statuses []statusRecord `json:"statuses"`
	}
	path := fmt.Sprintf("/repos/%s/%s/commits/%s/status", esc(owner), esc(repo), esc(ref))
	if err := c.request(ctx, http.MethodGet, path, nil, &response, "application/vnd.github+json"); err != nil {
		return gitea.CombinedStatus{}, err
	}
	out := gitea.CombinedStatus{State: response.State}
	for _, st := range response.Statuses {
		out.Statuses = append(out.Statuses, struct {
			Context     string `json:"context"`
			Status      string `json:"status"`
			Description string `json:"description"`
			TargetURL   string `json:"target_url"`
		}{Context: st.Context, Status: st.State, Description: st.Description})
	}
	return out, nil
}

func (c *Client) AddCommentReaction(ctx context.Context, owner, repo string, commentID int64, content string) error {
	return c.addReaction(ctx, fmt.Sprintf("/repos/%s/%s/issues/comments/%d/reactions", esc(owner), esc(repo), commentID), content)
}

func (c *Client) AddReviewCommentReaction(ctx context.Context, owner, repo string, commentID int64, content string) error {
	return c.addReaction(ctx, fmt.Sprintf("/repos/%s/%s/pulls/comments/%d/reactions", esc(owner), esc(repo), commentID), content)
}

func (c *Client) AddIssueReaction(ctx context.Context, owner, repo string, number int64, content string) error {
	return c.addReaction(ctx, fmt.Sprintf("/repos/%s/%s/issues/%d/reactions", esc(owner), esc(repo), number), content)
}

// ListPullReviewComments returns comments for one review and caches their GraphQL
// thread IDs so ResolveReviewComment can resolve the corresponding thread.
func (c *Client) ListPullReviewComments(ctx context.Context, owner, repo string, number, reviewID int64) ([]gitea.PullReviewComment, error) {
	const query = `query($owner:String!, $repo:String!, $number:Int!, $cursor:String) { repository(owner:$owner,name:$repo) { pullRequest(number:$number) { reviewThreads(first:100,after:$cursor) { nodes { id isResolved comments(first:100) { nodes { fullDatabaseId author { login } pullRequestReview { fullDatabaseId } } } pageInfo { hasNextPage endCursor } } pageInfo { hasNextPage endCursor } } } } }`
	type gqlComment struct {
		DatabaseID string `json:"fullDatabaseId"`
		Author     *struct {
			Login string `json:"login"`
		} `json:"author"`
		Review *struct {
			DatabaseID string `json:"fullDatabaseId"`
		} `json:"pullRequestReview"`
	}
	type gqlThread struct {
		ID         string `json:"id"`
		IsResolved bool   `json:"isResolved"`
		Comments   struct {
			Nodes []gqlComment `json:"nodes"`
		} `json:"comments"`
	}
	var result []gitea.PullReviewComment
	cursor := ""
	for page := 0; page < 100; page++ {
		var data struct {
			Repository *struct {
				PullRequest *struct {
					ReviewThreads struct {
						Nodes    []gqlThread `json:"nodes"`
						PageInfo struct {
							HasNextPage bool   `json:"hasNextPage"`
							EndCursor   string `json:"endCursor"`
						} `json:"pageInfo"`
					} `json:"reviewThreads"`
				} `json:"pullRequest"`
			} `json:"repository"`
		}
		vars := map[string]any{"owner": owner, "repo": repo, "number": number, "cursor": nil}
		if cursor != "" {
			vars["cursor"] = cursor
		}
		if err := c.graphql(ctx, query, vars, &data); err != nil {
			return nil, err
		}
		if data.Repository == nil || data.Repository.PullRequest == nil {
			return nil, fmt.Errorf("GitHub GraphQL returned no pull request")
		}
		threads := data.Repository.PullRequest.ReviewThreads
		for _, thread := range threads.Nodes {
			for _, comment := range thread.Comments.Nodes {
				commentID, parseErr := strconv.ParseInt(comment.DatabaseID, 10, 64)
				reviewCommentID := int64(0)
				if comment.Review != nil {
					reviewCommentID, _ = strconv.ParseInt(comment.Review.DatabaseID, 10, 64)
				}
				if parseErr != nil || commentID == 0 || reviewCommentID != reviewID {
					continue
				}
				login := ""
				if comment.Author != nil {
					login = comment.Author.Login
				}
				var resolver *gitea.User
				if thread.IsResolved {
					resolver = &gitea.User{Login: "resolved"}
				}
				result = append(result, gitea.PullReviewComment{ID: commentID, User: gitea.User{Login: login}, Resolver: resolver})
				c.threadMu.Lock()
				c.threadIDs[commentID] = thread.ID
				c.threadMu.Unlock()
			}
		}
		if !threads.PageInfo.HasNextPage {
			return result, nil
		}
		cursor = threads.PageInfo.EndCursor
		if cursor == "" {
			return nil, fmt.Errorf("GitHub GraphQL returned an empty review-thread cursor")
		}
	}
	return nil, fmt.Errorf("GitHub review thread list exceeded 100 pages")
}

func (c *Client) ResolveReviewComment(ctx context.Context, owner, repo string, commentID int64) error {
	c.threadMu.Lock()
	threadID := c.threadIDs[commentID]
	c.threadMu.Unlock()
	if threadID == "" {
		return fmt.Errorf("GitHub review thread for comment %d is unknown; list its review comments first", commentID)
	}
	const mutation = `mutation($threadId:ID!) { resolveReviewThread(input:{threadId:$threadId}) { thread { id isResolved } } }`
	var result struct {
		ResolveReviewThread *struct {
			Thread *struct {
				ID         string `json:"id"`
				IsResolved bool   `json:"isResolved"`
			} `json:"thread"`
		} `json:"resolveReviewThread"`
	}
	if err := c.graphql(ctx, mutation, map[string]any{"threadId": threadID}, &result); err != nil {
		return err
	}
	if result.ResolveReviewThread == nil || result.ResolveReviewThread.Thread == nil || !result.ResolveReviewThread.Thread.IsResolved {
		return fmt.Errorf("GitHub did not resolve review thread")
	}
	return nil
}

func (c *Client) graphql(ctx context.Context, query string, variables, out any) error {
	endpoint := c.baseURL + "/graphql"
	if strings.HasSuffix(c.baseURL, "/api/v3") {
		endpoint = strings.TrimSuffix(c.baseURL, "/api/v3") + "/api/graphql"
	}
	var response struct {
		Data   json.RawMessage `json:"data"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := c.requestURL(ctx, endpoint, http.MethodPost, map[string]any{"query": query, "variables": variables}, &response, "application/vnd.github+json"); err != nil {
		return err
	}
	if len(response.Errors) > 0 {
		return fmt.Errorf("GitHub GraphQL: %s", response.Errors[0].Message)
	}
	if len(response.Data) == 0 {
		return fmt.Errorf("GitHub GraphQL returned no data")
	}
	return json.Unmarshal(response.Data, out)
}

func (c *Client) addReaction(ctx context.Context, path, content string) error {
	return c.request(ctx, http.MethodPost, path, map[string]string{"content": content}, nil, "application/vnd.github+json")
}

func (c *Client) EnsureAndAddLabels(ctx context.Context, owner, repo string, number int64, labels []string) error {
	if len(labels) == 0 {
		return nil
	}
	known := make(map[string]bool)
	for page := 1; page <= 10; page++ {
		var existing []struct {
			Name string `json:"name"`
		}
		path := fmt.Sprintf("/repos/%s/%s/labels?per_page=100&page=%d", esc(owner), esc(repo), page)
		if err := c.request(ctx, http.MethodGet, path, nil, &existing, "application/vnd.github+json"); err != nil {
			return err
		}
		for _, label := range existing {
			known[strings.ToLower(label.Name)] = true
		}
		if len(existing) < 100 {
			break
		}
	}
	for _, name := range labels {
		name = strings.TrimSpace(name)
		if name == "" || known[strings.ToLower(name)] {
			continue
		}
		_ = c.request(ctx, http.MethodPost, fmt.Sprintf("/repos/%s/%s/labels", esc(owner), esc(repo)), map[string]string{"name": name, "color": githubLabelColor(name)}, nil, "application/vnd.github+json")
	}
	return c.request(ctx, http.MethodPost, fmt.Sprintf("/repos/%s/%s/issues/%d/labels", esc(owner), esc(repo), number), map[string][]string{"labels": labels}, nil, "application/vnd.github+json")
}

// RemoveLabelsWithPrefix detaches every label on the pull request whose name starts with prefix,
// except the names in keep (see gitea.Client.RemoveLabelsWithPrefix).
func (c *Client) RemoveLabelsWithPrefix(ctx context.Context, owner, repo string, number int64, prefix string, keep []string) error {
	if prefix == "" {
		return fmt.Errorf("label prefix is required")
	}
	keepSet := make(map[string]bool, len(keep))
	for _, k := range keep {
		keepSet[strings.ToLower(strings.TrimSpace(k))] = true
	}
	base := fmt.Sprintf("/repos/%s/%s/issues/%d/labels", esc(owner), esc(repo), number)
	var current []struct {
		Name string `json:"name"`
	}
	if err := c.request(ctx, http.MethodGet, base+"?per_page=100", nil, &current, "application/vnd.github+json"); err != nil {
		return err
	}
	var firstErr error
	for _, lbl := range current {
		lower := strings.ToLower(lbl.Name)
		if !strings.HasPrefix(lower, strings.ToLower(prefix)) || keepSet[lower] {
			continue
		}
		if err := c.request(ctx, http.MethodDelete, base+"/"+esc(lbl.Name), nil, nil, "application/vnd.github+json"); err != nil && firstErr == nil && !strings.Contains(err.Error(), "404") {
			firstErr = err
		}
	}
	return firstErr
}

func githubLabelColor(name string) string {
	switch {
	case strings.EqualFold(name, "security"):
		return "d73a4a"
	case strings.EqualFold(name, "tests"):
		return "0e8a16"
	case strings.HasPrefix(strings.ToLower(name), "size/"):
		return "5319e7"
	default:
		return "0075ca"
	}
}

func (c *Client) RequestReviewers(ctx context.Context, owner, repo string, number int64, reviewers []string) error {
	if len(reviewers) == 0 {
		return nil
	}
	path := fmt.Sprintf("/repos/%s/%s/pulls/%d/requested_reviewers", esc(owner), esc(repo), number)
	return c.request(ctx, http.MethodPost, path, map[string][]string{"reviewers": reviewers}, nil, "application/vnd.github+json")
}

func (c *Client) UpsertStickyComment(ctx context.Context, owner, repo string, number int64, marker, body string) error {
	if !strings.Contains(body, marker) {
		body = marker + "\n" + body
	}
	for page := 1; page <= 20; page++ {
		path := fmt.Sprintf("/repos/%s/%s/issues/%d/comments?per_page=100&page=%d", esc(owner), esc(repo), number, page)
		var comments []struct {
			ID   int64  `json:"id"`
			Body string `json:"body"`
		}
		if err := c.request(ctx, http.MethodGet, path, nil, &comments, "application/vnd.github+json"); err != nil {
			return err
		}
		for _, cm := range comments {
			if strings.Contains(cm.Body, marker) {
				return c.request(ctx, http.MethodPatch, fmt.Sprintf("/repos/%s/%s/issues/comments/%d", esc(owner), esc(repo), cm.ID), map[string]string{"body": body}, nil, "application/vnd.github+json")
			}
		}
		if len(comments) < 100 {
			break
		}
	}
	return c.PostComment(ctx, owner, repo, number, body)
}

func (c *Client) SetCommitStatus(ctx context.Context, owner, repo, sha, state, description string) error {
	if state == "error" {
		state = "error"
	}
	payload := map[string]string{"state": state, "description": description, "context": "codespider"}
	return c.request(ctx, http.MethodPost, fmt.Sprintf("/repos/%s/%s/statuses/%s", esc(owner), esc(repo), esc(sha)), payload, nil, "application/vnd.github+json")
}

func (c *Client) IsCollaborator(ctx context.Context, owner, repo, username string) (bool, error) {
	if username == "" {
		return false, nil
	}
	var p struct {
		Permission string `json:"permission"`
	}
	err := c.request(ctx, http.MethodGet, fmt.Sprintf("/repos/%s/%s/collaborators/%s/permission", esc(owner), esc(repo), esc(username)), nil, &p, "application/vnd.github+json")
	if err != nil {
		if strings.Contains(err.Error(), "404") {
			return false, nil
		}
		return false, err
	}
	return p.Permission == "admin" || p.Permission == "write" || p.Permission == "maintain", nil
}

func esc(s string) string { return url.PathEscape(s) }

func (c *Client) request(ctx context.Context, method, path string, in, out any, accept string) error {
	return c.requestURL(ctx, c.baseURL+path, method, in, out, accept)
}

func (c *Client) requestURL(ctx context.Context, endpoint, method string, in, out any, accept string) error {
	var body io.Reader
	if in != nil {
		data, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", accept)
	req.Header.Set("X-GitHub-Api-Version", "2026-03-10")
	req.Header.Set("User-Agent", "CodeSpider")
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	token := c.token
	if c.tokenSource != nil {
		var err error
		token, err = c.tokenSource.Token(ctx)
		if err != nil {
			return fmt.Errorf("get GitHub access token: %w", err)
		}
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	const maxResponseBytes = 5 << 20
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return err
	}
	if len(data) > maxResponseBytes {
		return fmt.Errorf("github API %s: response exceeds %d bytes", resp.Status, maxResponseBytes)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("github API %s: %s", resp.Status, strings.TrimSpace(string(data)))
	}
	if out != nil && len(data) > 0 {
		if p, ok := out.(*string); ok {
			*p = string(data)
			return nil
		}
		return json.Unmarshal(data, out)
	}
	return nil
}
