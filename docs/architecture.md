# CodeSpider Architecture

CodeSpider is a self-hostable, **24/7 agentic PR review daemon** for Gitea.

## High-Level Flow

```text
Gitea Webhook (POST /webhook)
   │  HMAC-SHA256 verified
   ▼
WebhookHandler (internal/gitea)
   │  Normalizes pull_request & @codespider issue_comment events
   │  Filters draft/WIP and bot PRs
   ▼
Worker Pool (internal/worker)
   │  - Deduplicates already-reviewed SHAs (internal/store)
   │  - Cancels superseded runs when new commits arrive on the same PR
   │  - Checks out ephemeral git worktree at head SHA (internal/workspace)
   │  - Loads AGENTS.md / .codespider.yaml & filters ignore_paths (internal/repoconfig)
   ▼
Agent Loop (internal/agent + internal/llm + internal/skills)
   │  - Loads skills (e.g. security, code-quality) + repo instructions
   │  - Calls OpenAI-compatible LLM with tool definitions
   │  - Executes read_file / search_code / get_pr_diff / add_inline_comment (with 1-click suggestions)
   │  - Enforces step budget, token budget, and duplicate-call guard
   ▼
Gitea REST API (internal/gitea)
   └─ Posts PR summary + inline comments + commit status
```

## Key Packages

- `cmd/codespider`: Daemon entrypoint (`/webhook`, `/healthz`, `/readyz`, `/status`, graceful `SIGTERM` shutdown).
- `internal/config`: YAML configuration (`codespider.yaml`, `-f`, `CODESPIDER_CONFIG_PATH`) and validation.
- `internal/gitea`: Webhook HMAC verification, event normalization, and Gitea v1 REST client.
- `internal/workspace`: Bare git mirror cache and isolated per-PR worktrees with path-traversal protection.
- `internal/llm`: OpenAI-compatible `/chat/completions` client with tool-calling support.
- `internal/skills`: Loads `SKILL.md` modules into the agent's system prompt.
- `internal/repoconfig`: Loads per-repo `AGENTS.md`, review instruction files, and `.codespider.yaml` (`enabled`, `ignore_paths`, `instructions`).
- `internal/tools`: Sandboxed read-only codebase tools and Gitea review/reply tools.
- `internal/agent`: Autonomous tool-calling loop with step/token/loop guardrails.
- `internal/store`: Atomic JSON persistence (`data/state.json`) for reviewed SHAs and recent run history.
- `internal/worker`: Concurrent worker pool with per-PR cancellation and status reporting.
