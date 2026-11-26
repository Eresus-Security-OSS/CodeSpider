# CodeSpider

Self-hostable, **24/7 agentic PR reviewer** for **Gitea**.

CodeSpider runs as a lightweight daemon alongside your Gitea instance. When a pull request is opened, updated, or `@codespider` is mentioned in a PR comment, it checks out an isolated git worktree, inspects the diff and surrounding codebase using tool calls, and posts inline review comments, summaries, and commit statuses.

## Features

- **24/7 Webhook Daemon:** Listens on `POST /webhook` with HMAC-SHA256 verification (`X-Gitea-Signature`), plus `/healthz`, `/readyz`, and `/status`.
- **Agentic Code Exploration:** Navigates the PR's git worktree using `get_pr_diff`, `read_file`, `search_code`, and `list_pr_comments` before commenting.
- **Interactive `@codespider` Replies:** Respond to developer questions directly in PR comment threads (with self-loop protection).
- **Skill-Guided Reviews:** Loads `SKILL.md` modules into the agent prompt—includes built-in [`security`](skills/security/SKILL.md) and [`code-quality`](skills/code-quality/SKILL.md) skills.
- **Opt-In Write Mode (`AGENT_ENABLE_WRITE=true`):** Enables `write_file`, `edit_file`, and `commit_and_push` inside the PR worktree with path-traversal and `.git/` protection.
- **Any OpenAI-Compatible LLM:** Works with OpenAI, vLLM, LiteLLM, OpenRouter, or any `/v1/chat/completions` endpoint with tool calling.
- **24/7 Guardrails:** Deduplicates reviewed commit SHAs in `data/state.json`, cancels superseded in-flight reviews on new pushes, and enforces step, token, and duplicate-call limits.

## Quick Start

```bash
cp .env.example .env
# Edit .env with your GITEA_BASE_URL, GITEA_TOKEN, GITEA_WEBHOOK_SECRET, and LLM settings
set -a && source .env && set +a

go build -o codespider ./cmd/codespider
./codespider
```

## Documentation

- [Architecture](docs/architecture.md)
- [Gitea Setup Guide](docs/gitea-setup.md)
- [Configuration Reference](docs/configuration.md)

## Development

```bash
go build ./...
go vet ./...
go test -v ./...
```
