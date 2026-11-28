# AGENTS.md

Guidelines for AI coding agents and automated code reviewers working on **CodeSpider** (a 24/7 agentic Gitea/GitHub PR review daemon in Go).

## Project Architecture

- **Language & Dependencies:** Go (`go.mod` targets `go 1.26.11`) with **zero external dependencies** (standard library only). Do not add third-party Go modules unless explicitly requested.
- **Entrypoint:** `cmd/codespider/main.go` — parses `-f` / `CODESPIDER_CONFIG_PATH` / `codespider.yaml`, selects a forge provider, loads skills, starts the worker pool, and serves `/webhook`, `/healthz`, `/readyz`, `/status`.
- **Key Packages:**
  - `internal/config`: Zero-dependency YAML loader (`codespider.yaml`), `${ENV_VAR}` expansion, and validation.
  - `internal/gitea`: Gitea HMAC-SHA256 webhook verification, draft/bot PR filtering, normalized PR types, and Gitea v1 REST client.
  - `internal/provider`: `ForgeProvider` interface and Gitea adapter; `internal/provider/github` implements REST operations and signed GitHub webhook normalization using caller-supplied credentials.
  - `internal/workspace`: Bare git mirror cache and isolated per-PR worktrees with path-traversal protection (`ResolveSafePath`).
  - `internal/repoconfig`: Loads repo-native `AGENTS.md`, instruction files, and `.codespider.yaml` (`enabled`, `ignore_paths`, `instructions`).
  - `internal/skills`: Loads `SKILL.md` modules from `skills/` into the system prompt.
  - `internal/tools`: Sandboxed codebase tools (`get_pr_diff`, `read_file`, `search_code`), forge review/comment tools (`add_inline_comment` with 1-click `suggestion` blocks, `submit_review`, `reply_comment`), and opt-in write tools.
  - `internal/agent` & `internal/llm`: OpenAI-compatible `/chat/completions` client and autonomous tool-calling loop with step, token, and duplicate-call guardrails.
  - `internal/worker` & `internal/store`: Concurrent worker pool with per-PR superseding and atomic JSON state persistence (`data/state.json`).

## Build & Verification

Run before finishing any code change:

```bash
go build ./...
go vet ./...
go test -race -v ./...
```

For Docker/Compose changes, also validate:

```bash
docker compose -f docker-compose.yaml config -q
docker compose -f docker-compose.dev.yaml config -q
```

## Coding & Security Rules

1. **Path & Git Safety:** All file reads/writes in PR worktrees must go through `workspace.ResolveSafePath` (and `resolveWritablePath` for writes, blocking `.git/`). Never shell out with unsanitized user input.
2. **HTTP & Webhook Hardening:**
   - Verify Gitea `X-Gitea-Signature` and GitHub `X-Hub-Signature-256` using constant-time `hmac.Equal`.
   - Always wrap HTTP response/request body reads with `io.LimitReader` and close `resp.Body`.
   - Always propagate `context.Context` and enforce timeouts on external HTTP and `git` calls.
3. **Secrets:** Never log or commit tokens, webhook secrets, or LLM API keys. `codespider.yaml` is gitignored; update `codespider.example.yaml` and `docs/configuration.md` when adding config keys.
4. **Concurrency & State:** Guard shared maps/state with mutexes (`worker.Pool`, `store.Store`, `tools.ReviewState`, `workspace.Manager`) and persist state atomically via temp-file + `os.Rename`.
5. **Tests:** Keep tests offline and deterministic using `httptest.NewServer` and `t.TempDir()`. Cover both happy paths and security/error paths.
