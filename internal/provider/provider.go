// Package provider defines an extensible Git forge abstraction for CodeSpider.
// Gitea (and Forgejo via v1 API compatibility) is the primary validated implementation.
package provider

import (
	"context"

	"github.com/Eresus-Security-OSS/CodeSpider/internal/gitea"
)

// ForgeProvider abstracts pull request reads, reviews, comments, and permission checks.
type ForgeProvider interface {
	Name() string
	GetPullRequest(ctx context.Context, owner, repo string, number int64) (gitea.PullRequest, error)
	GetPullRequestDiff(ctx context.Context, owner, repo string, number int64) (string, error)
	SubmitReview(ctx context.Context, owner, repo string, number int64, review gitea.CreateReviewRequest) error
	PostComment(ctx context.Context, owner, repo string, number int64, body string) error
	UpsertStickyComment(ctx context.Context, owner, repo string, number int64, marker, body string) error
	SetCommitStatus(ctx context.Context, owner, repo, sha, state, description string) error
	IsCollaborator(ctx context.Context, owner, repo, username string) (bool, error)
}

// GiteaAdapter adapts *gitea.Client to ForgeProvider.
type GiteaAdapter struct {
	Client *gitea.Client
}

// Name returns "gitea".
func (a *GiteaAdapter) Name() string { return "gitea" }

func (a *GiteaAdapter) GetPullRequest(ctx context.Context, owner, repo string, number int64) (gitea.PullRequest, error) {
	return a.Client.GetPullRequest(ctx, owner, repo, number)
}

func (a *GiteaAdapter) GetPullRequestDiff(ctx context.Context, owner, repo string, number int64) (string, error) {
	return a.Client.GetPullRequestDiff(ctx, owner, repo, number)
}

func (a *GiteaAdapter) SubmitReview(ctx context.Context, owner, repo string, number int64, review gitea.CreateReviewRequest) error {
	return a.Client.CreateReview(ctx, owner, repo, number, review)
}

func (a *GiteaAdapter) PostComment(ctx context.Context, owner, repo string, number int64, body string) error {
	return a.Client.PostComment(ctx, owner, repo, number, body)
}

func (a *GiteaAdapter) UpsertStickyComment(ctx context.Context, owner, repo string, number int64, marker, body string) error {
	return a.Client.UpsertStickyComment(ctx, owner, repo, number, marker, body)
}

func (a *GiteaAdapter) SetCommitStatus(ctx context.Context, owner, repo, sha, state, description string) error {
	return a.Client.SetCommitStatus(ctx, owner, repo, sha, state, description)
}

func (a *GiteaAdapter) IsCollaborator(ctx context.Context, owner, repo, username string) (bool, error) {
	return a.Client.IsCollaborator(ctx, owner, repo, username)
}
