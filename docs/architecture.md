# CodeSpider Architecture

CodeSpider is a self-hostable, **24/7 agentic PR review daemon** for Gitea,
Forgejo, GitHub.com, and GitHub Enterprise Server.

## High-Level Flow

```text
Configured Forge Webhook (POST /webhook)
   │  Provider-specific HMAC-SHA256 verified
   ▼
Provider webhook handler (`internal/gitea` or `internal/provider/github`)
   │  Normalizes pull_request & @codespider issue_comment events
   │  Filters draft/WIP and bot PRs
   ▼
Worker Pool (internal/worker)
   │  - Deduplicates already-reviewed SHAs (internal/store)
   │  - Periodically reconciles open PRs to recover missed webhooks
   │  - Cancels superseded runs when new commits arrive on the same PR
   │  - Checks out ephemeral git worktree at head SHA (internal/workspace)
   │  - Computes incremental commit diffs when a prior SHA was reviewed
   │  - Loads AGENTS.md / .codespider.yaml & filters ignore_paths (internal/repoconfig)
   ▼
Agent Loop (internal/agent + internal/llm + internal/skills)
   │  - Loads skills (e.g. security, code-quality, performance, concurrency) + repo instructions
   │  - Calls OpenAI-compatible LLM with retry/backoff and tool definitions
   │  - Executes read_file / search_code / list_files / get_pr_diff / get_incremental_diff / add_inline_comment (with 1-click suggestions)
   │  - Enforces step budget, token budget, severity gate, and duplicate-call guard
   ▼
Configured Forge REST API (internal/provider)
   └─ Posts PR summary + inline comments + 👀 reactions + commit status
```

## Key Packages

- `cmd/codespider`: Daemon entrypoint (`/webhook`, `/healthz`, `/readyz`, `/status`, `/metrics`, `/` dashboard, graceful `SIGTERM` shutdown).
- `internal/config`: YAML configuration (`codespider.yaml`, `-f`, `CODESPIDER_CONFIG_PATH`) and validation.
- `internal/gitea`: Gitea webhook HMAC verification, slash-command parsing, event normalization, Gitea v1 REST client, and normalized PR data types.
- `internal/provider`: Shared `ForgeProvider` interface and Gitea adapter.
- `internal/provider/github`: GitHub REST implementation of `ForgeProvider`,
  including paginated PR/repository reads, reviews, comments, reactions,
  statuses, labels, reviewers, and collaborator checks. Callers supply a
  GitHub static or App installation token and optional Enterprise API URL.
- `internal/workspace`: Bare git mirror cache, isolated per-PR worktrees, symlink-safe path resolution, and secret redaction.
- `internal/llm`: OpenAI-compatible `/chat/completions` client with retry/backoff and tool-calling support.
- `internal/skills`: Loads `SKILL.md` modules into the agent's system prompt.
- `internal/repoconfig`: Loads per-repo `AGENTS.md`, review instruction files, and `.codespider.yaml` (`enabled`, `min_severity`, `skills`, `ignore_paths`, `instructions`).
- `internal/tools`: Sandboxed codebase tools, line-annotated diffs, severity filtering, and provider-backed review/reply tools.
- `internal/agent`: Autonomous tool-calling loop with step/token/loop guardrails and budget-exhaustion auto-submission.
- `internal/metrics`: Thread-safe counters and Prometheus/JSON metric snapshots.
- `internal/store`: Atomic JSON persistence (`data/state.json`) for reviewed SHAs and recent run history.
- `internal/worker`: Concurrent worker pool with per-PR cancellation, periodic reconciler, and status reporting.
