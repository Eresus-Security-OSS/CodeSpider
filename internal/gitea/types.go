// Package gitea provides webhook handling and REST API bindings for Gitea.
package gitea

import "time"

// PullRequestEvent represents a Gitea pull_request webhook payload.
type PullRequestEvent struct {
	Action      string      `json:"action"`
	Number      int64       `json:"number"`
	PullRequest PullRequest `json:"pull_request"`
	Repository  Repository  `json:"repository"`
	Sender      User        `json:"sender"`
}

// IssueCommentEvent represents a Gitea issue_comment / pull_request_comment webhook payload.
type IssueCommentEvent struct {
	Action     string     `json:"action"`
	Issue      Issue      `json:"issue"`
	Comment    Comment    `json:"comment"`
	Repository Repository `json:"repository"`
	Sender     User       `json:"sender"`
	IsPull     bool       `json:"is_pull"`
}

// PullRequest models key fields of a Gitea pull request.
type PullRequest struct {
	ID        int64     `json:"id"`
	Number    int64     `json:"number"`
	State     string    `json:"state"`
	Title     string    `json:"title"`
	Body      string    `json:"body"`
	Draft     bool      `json:"draft"`
	HTMLURL   string    `json:"html_url"`
	DiffURL   string    `json:"diff_url"`
	Head      BranchRef `json:"head"`
	Base      BranchRef `json:"base"`
	User      User      `json:"user"`
	Merged    bool      `json:"merged"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// BranchRef describes a git ref and SHA on a PR.
type BranchRef struct {
	Label string     `json:"label"`
	Ref   string     `json:"ref"`
	SHA   string     `json:"sha"`
	Repo  Repository `json:"repo"`
}

// Repository models a Gitea repository.
type Repository struct {
	ID            int64  `json:"id"`
	Name          string `json:"name"`
	FullName      string `json:"full_name"`
	CloneURL      string `json:"clone_url"`
	SSHURL        string `json:"ssh_url"`
	DefaultBranch string `json:"default_branch"`
	Owner         User   `json:"owner"`
}

// Issue models a Gitea issue or PR summary object inside comment webhooks.
type Issue struct {
	ID          int64       `json:"id"`
	Number      int64       `json:"number"`
	Title       string      `json:"title"`
	Body        string      `json:"body"`
	State       string      `json:"state"`
	PullRequest *PullMarker `json:"pull_request,omitempty"`
}

// PullMarker is non-nil when an Issue is a Pull Request.
type PullMarker struct {
	Merged bool `json:"merged"`
}

// Comment models a Gitea issue/PR comment.
type Comment struct {
	ID        int64     `json:"id"`
	Body      string    `json:"body"`
	User      User      `json:"user"`
	HTMLURL   string    `json:"html_url"`
	CreatedAt time.Time `json:"created_at"`
}

// User models a Gitea user.
type User struct {
	ID       int64  `json:"id"`
	Username string `json:"username"`
	Login    string `json:"login"`
	Type     string `json:"type"`
}

// ReviewComment is a single inline comment in a Gitea PR review submission.
type ReviewComment struct {
	Path       string `json:"path"`
	Body       string `json:"body"`
	NewLineNum int64  `json:"new_position,omitempty"`
	OldLineNum int64  `json:"old_position,omitempty"`
}

// CreateReviewRequest is the payload for POST /repos/{owner}/{repo}/pulls/{index}/reviews.
type CreateReviewRequest struct {
	CommitID string          `json:"commit_id,omitempty"`
	Body     string          `json:"body"`
	Event    string          `json:"event"` // COMMENT, APPROVE, REQUEST_CHANGES
	Comments []ReviewComment `json:"comments,omitempty"`
}

// PullReview represents an existing PR review returned by Gitea.
type PullReview struct {
	ID          int64     `json:"id"`
	State       string    `json:"state"`
	Body        string    `json:"body"`
	CommitID    string    `json:"commit_id"`
	User        User      `json:"user"`
	SubmittedAt time.Time `json:"submitted_at"`
}

// PullReviewComment is an inline comment attached to a PR review. Resolver is non-nil once the thread is resolved.
type PullReviewComment struct {
	ID       int64  `json:"id"`
	Body     string `json:"body"`
	Path     string `json:"path"`
	User     User   `json:"user"`
	Resolver *User  `json:"resolver"`
}

// Resolved reports whether the comment thread has been marked resolved.
func (c PullReviewComment) Resolved() bool {
	return c.Resolver != nil && (c.Resolver.ID != 0 || c.Resolver.Username != "" || c.Resolver.Login != "")
}

// PullReviewCommentEvent represents a Gitea pull_request_review_comment webhook payload.
type PullReviewCommentEvent struct {
	Action      string      `json:"action"`
	PullRequest PullRequest `json:"pull_request"`
	Repository  Repository  `json:"repository"`
	Sender      User        `json:"sender"`
	Comment     struct {
		ID       int64  `json:"id"`
		Body     string `json:"body"`
		Path     string `json:"path"`
		Line     int64  `json:"position"`
		NewLine  int64  `json:"new_position"`
		DiffHunk string `json:"diff_hunk"`
		User     User   `json:"user"`
	} `json:"comment"`
}

// Label models a Gitea repository label.
type Label struct {
	ID    int64  `json:"id"`
	Name  string `json:"name"`
	Color string `json:"color"`
}

// CombinedStatus models the combined commit status returned by Gitea.
type CombinedStatus struct {
	State    string `json:"state"`
	Statuses []struct {
		Context     string `json:"context"`
		Status      string `json:"status"`
		Description string `json:"description"`
		TargetURL   string `json:"target_url"`
	} `json:"statuses"`
}
