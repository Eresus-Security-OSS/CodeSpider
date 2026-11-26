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
	ID          int64        `json:"id"`
	Number      int64        `json:"number"`
	Title       string       `json:"title"`
	Body        string       `json:"body"`
	State       string       `json:"state"`
	PullRequest *PullMarker  `json:"pull_request,omitempty"`
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
