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
	ListOpenPullRequests(ctx context.Context, owner, repo string) ([]gitea.PullRequest, error)
	ListAccessibleRepos(ctx context.Context) ([]gitea.Repository, error)
	GetPullRequestDiff(ctx context.Context, owner, repo string, number int64) (string, error)
	SubmitReview(ctx context.Context, owner, repo string, number int64, review gitea.CreateReviewRequest) error
	PostComment(ctx context.Context, owner, repo string, number int64, body string) error
	UpsertStickyComment(ctx context.Context, owner, repo string, number int64, marker, body string) error
	ListPRComments(ctx context.Context, owner, repo string, number int64) ([]gitea.Comment, error)
	ListPullReviews(ctx context.Context, owner, repo string, number int64) ([]gitea.PullReview, error)
	GetCombinedCommitStatus(ctx context.Context, owner, repo, ref string) (gitea.CombinedStatus, error)
	AddCommentReaction(ctx context.Context, owner, repo string, commentID int64, content string) error
	AddReviewCommentReaction(ctx context.Context, owner, repo string, commentID int64, content string) error
	AddIssueReaction(ctx context.Context, owner, repo string, number int64, content string) error
	EnsureAndAddLabels(ctx context.Context, owner, repo string, number int64, labels []string) error
	RequestReviewers(ctx context.Context, owner, repo string, number int64, reviewers []string) error
	SetCommitStatus(ctx context.Context, owner, repo, sha, state, description string) error
	IsCollaborator(ctx context.Context, owner, repo, username string) (bool, error)
}

// LabelPrefixReplacer is implemented by providers that can detach outdated labels from a PR.
type LabelPrefixReplacer interface {
	RemoveLabelsWithPrefix(ctx context.Context, owner, repo string, number int64, prefix string, keep []string) error
}

// ReviewThreadResolver is implemented by providers that can resolve inline review threads.
type ReviewThreadResolver interface {
	ListPullReviewComments(ctx context.Context, owner, repo string, number, reviewID int64) ([]gitea.PullReviewComment, error)
	ResolveReviewComment(ctx context.Context, owner, repo string, commentID int64) error
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

func (a *GiteaAdapter) ListOpenPullRequests(ctx context.Context, owner, repo string) ([]gitea.PullRequest, error) {
	return a.Client.ListOpenPullRequests(ctx, owner, repo)
}

func (a *GiteaAdapter) ListAccessibleRepos(ctx context.Context) ([]gitea.Repository, error) {
	return a.Client.ListAccessibleRepos(ctx)
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

func (a *GiteaAdapter) ListPRComments(ctx context.Context, owner, repo string, number int64) ([]gitea.Comment, error) {
	return a.Client.ListPRComments(ctx, owner, repo, number)
}

func (a *GiteaAdapter) ListPullReviews(ctx context.Context, owner, repo string, number int64) ([]gitea.PullReview, error) {
	return a.Client.ListPullReviews(ctx, owner, repo, number)
}

func (a *GiteaAdapter) GetCombinedCommitStatus(ctx context.Context, owner, repo, ref string) (gitea.CombinedStatus, error) {
	return a.Client.GetCombinedCommitStatus(ctx, owner, repo, ref)
}

func (a *GiteaAdapter) ListPullReviewComments(ctx context.Context, owner, repo string, number, reviewID int64) ([]gitea.PullReviewComment, error) {
	return a.Client.ListPullReviewComments(ctx, owner, repo, number, reviewID)
}

func (a *GiteaAdapter) ResolveReviewComment(ctx context.Context, owner, repo string, commentID int64) error {
	return a.Client.ResolveReviewComment(ctx, owner, repo, commentID)
}

func (a *GiteaAdapter) AddCommentReaction(ctx context.Context, owner, repo string, commentID int64, content string) error {
	return a.Client.AddCommentReaction(ctx, owner, repo, commentID, content)
}

func (a *GiteaAdapter) AddReviewCommentReaction(ctx context.Context, owner, repo string, commentID int64, content string) error {
	return nil // Gitea exposes reactions for issue comments, but not review comments.
}

func (a *GiteaAdapter) AddIssueReaction(ctx context.Context, owner, repo string, number int64, content string) error {
	return a.Client.AddIssueReaction(ctx, owner, repo, number, content)
}

func (a *GiteaAdapter) EnsureAndAddLabels(ctx context.Context, owner, repo string, number int64, labels []string) error {
	return a.Client.EnsureAndAddLabels(ctx, owner, repo, number, labels)
}

func (a *GiteaAdapter) RemoveLabelsWithPrefix(ctx context.Context, owner, repo string, number int64, prefix string, keep []string) error {
	return a.Client.RemoveLabelsWithPrefix(ctx, owner, repo, number, prefix, keep)
}

func (a *GiteaAdapter) RequestReviewers(ctx context.Context, owner, repo string, number int64, reviewers []string) error {
	return a.Client.RequestReviewers(ctx, owner, repo, number, reviewers)
}

func (a *GiteaAdapter) SetCommitStatus(ctx context.Context, owner, repo, sha, state, description string) error {
	return a.Client.SetCommitStatus(ctx, owner, repo, sha, state, description)
}

func (a *GiteaAdapter) IsCollaborator(ctx context.Context, owner, repo, username string) (bool, error) {
	return a.Client.IsCollaborator(ctx, owner, repo, username)
}
