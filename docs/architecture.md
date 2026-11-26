# CodeSpider Architecture

CodeSpider is a self-hostable, **24/7 agentic PR review daemon** for Gitea.

## High-Level Flow

```text
Gitea Webhook (POST /webhook)
   │  HMAC-SHA256 verified
   ▼
WebhookHandler (internal/gitea)
   │  Normalizes pull_request & @codespider issue_comment events
   ▼
Worker Pool (internal/worker)
   │  - Deduplicates already-reviewed SHAs (internal/store)
   │  - Cancels superseded runs when new commits arrive on the same PR
   │  - Checks out ephemeral git worktree at head SHA (internal/workspace)
   ▼
Agent Loop (internal/agent + internal/llm + internal/skills)
   │  - Loads skills (e.g. security, code-quality)
   │  - Calls OpenAI-compatible LLM with tool definitions
   │  - Executes read_file / search_code / get_pr_diff / add_inline_comment
   │  - Enforces step budget, token budget, and duplicate-call guard
   ▼
Gitea REST API (internal/gitea)
   └─ Posts PR summary + inline comments + commit status
```

## Key Packages

- `cmd/codespider`: Daemon entrypoint (`/webhook`, `/healthz`, `/readyz`, `/status`, graceful `SIGTERM` shutdown).
- `internal/config`: Environment-based configuration and validation.
- `internal/gitea`: Webhook HMAC verification, event normalization, and Gitea v1 REST client.
- `internal/workspace`: Bare git mirror cache and isolated per-PR worktrees with path-traversal protection.
- `internal/llm`: OpenAI-compatible `/chat/completions` client with tool-calling support.
- `internal/skills`: Loads `SKILL.md` modules into the agent's system prompt.
- `internal/tools`: Sandboxed read-only codebase tools and Gitea review/reply tools.
- `internal/agent`: Autonomous tool-calling loop with step/token/loop guardrails.
- `internal/store`: Atomic JSON persistence (`data/state.json`) for reviewed SHAs and recent run history.
- `internal/worker`: Concurrent worker pool with per-PR cancellation and status reporting.
