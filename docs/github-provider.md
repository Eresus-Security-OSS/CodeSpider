# GitHub Setup and Provider

CodeSpider includes `internal/provider/github`, a standard-library-only REST
client that implements `provider.ForgeProvider`. Select it with
`forge.provider: github` to use GitHub webhook intake, reconciliation, and the
shared review worker. The package is also usable by in-repository integrations
and forks.

## Supported operations

The client implements:

- Read pull request metadata and the unified diff.
- Submit reviews with an optional summary and inline comments.
- Post and update marker-based sticky issue comments.
- Set a commit status using the `codespider` context.
- Check a user's repository permission (`write`, `maintain`, or `admin`).
- List open pull requests and repositories for periodic reconciliation.
- Add labels and request CODEOWNERS reviewers when repository policy enables them.

The daemon accepts a static Bearer token or creates and refreshes GitHub App
installation tokens automatically. App mode uses the configured RSA private
key and installation ID; mount the key as a read-only secret file. Grant the
App only the repository permissions needed by the features you use.

## Configure the daemon

Set these values in `codespider.yaml` (the example file includes a commented
GitHub alternative):

```yaml
forge:
  provider: github
  # Optional. Empty discovers repositories accessible to the token.
  repos: [acme/service]

github:
  api_url: https://api.github.com
  token: "${CODESPIDER_GITHUB_TOKEN}"
  webhook_secret: "${CODESPIDER_GITHUB_WEBHOOK_SECRET}"
  bot_username: "codespider[bot]"
```

For automatic GitHub App authentication, omit `token` and use:

```yaml
github:
  api_url: https://api.github.com
  webhook_secret: "${CODESPIDER_GITHUB_WEBHOOK_SECRET}"
  app_id: 123456
  installation_id: 987654321
  app_private_key_path: /run/secrets/codespider-github-app.pem
```

CodeSpider obtains an installation token on first use and refreshes it five
minutes before expiry. The same current token is used for API requests and git
fetches. The PEM key is read at daemon startup; restart after rotating it.

The selected credentials are used for GitHub API operations and HTTPS git
clone/fetch/push. For a static token, grant access to the repositories and
operations you enable, keep it out of YAML, and rotate it when it expires.
For GitHub Enterprise Server, set `api_url` to its REST endpoint, commonly
`https://github.example.com/api/v3`.

In GitHub, add a repository webhook targeting
`https://<codespider-host>/webhook`, choose `application/json`, set the same
secret as `github.webhook_secret`, and subscribe to:

- `pull_request` (opened, reopened, synchronize, and ready-for-review actions)
- `issue_comment` (PR conversation comments mentioning the configured bot)
- `pull_request_review_comment` (inline comments mentioning the configured bot)

GitHub signatures are verified from `X-Hub-Signature-256` using HMAC-SHA256 and
constant-time comparison. `/webhook` handles only the selected provider, so
run separate CodeSpider instances if you need Gitea and GitHub at the same
time.

## Use from Go

For GitHub.com, pass `https://api.github.com`. For GitHub Enterprise Server,
pass its REST API base URL, commonly `https://github.example.com/api/v3`.

```go
package main

import (
	"context"
	"os"

	"github.com/Eresus-Security-OSS/CodeSpider/internal/gitea"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/provider"
	githubprovider "github.com/Eresus-Security-OSS/CodeSpider/internal/provider/github"
)

func inspect(ctx context.Context, owner, repo string, number int64) error {
	token := os.Getenv("GITHUB_TOKEN")
	forge := provider.ForgeProvider(githubprovider.NewClient("https://api.github.com", token))
	pr, err := forge.GetPullRequest(ctx, owner, repo, number)
	if err != nil {
		return err
	}
	diff, err := forge.GetPullRequestDiff(ctx, owner, repo, number)
	if err != nil {
		return err
	}
	_ = pr
	_ = diff
	return forge.SubmitReview(ctx, owner, repo, number, gitea.CreateReviewRequest{
		Event: "COMMENT",
		Body:  "Review summary",
	})
}
```

The `internal` Go package visibility rule means this package is importable by
code inside the CodeSpider module, not by unrelated external modules. The
example is therefore for in-repository integrations or forks.

## Current boundaries

- The client has a 30-second HTTP timeout, sends the GitHub REST API version
  header, bounds response bodies, and honors caller contexts.
- Inline review comments use the shared review request type. GitHub may reject
  comments whose file line is not part of the current diff or whose token lacks
  review write permission.
- `/resolve` lists the bot's review comments through GraphQL and resolves their
  containing review threads. GitHub may reject the operation if the App lacks
  access to the pull request.
- The API adapter is unit tested with local HTTP fixtures; it has not been
  validated against a live GitHub.com or GitHub Enterprise instance.
- App private-key rotation takes effect after restarting the daemon.
