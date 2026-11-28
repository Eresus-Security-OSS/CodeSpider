# Configuration Reference

CodeSpider is configured via a YAML file (see [`codespider.example.yaml`](../codespider.example.yaml)).

Config file resolution order:
1. `-f <path>` CLI flag (`./codespider -f /etc/codespider/codespider.yaml`)
2. `CODESPIDER_CONFIG_PATH` environment variable
3. `./codespider.yaml` or `./codespider.yml` in the current working directory

String values support optional `${ENV_VAR}` expansion (for example, `api_key: "${LLM_API_KEY}"`).

## Daemon YAML Keys

| Key | Default | Required | Description |
| --- | --- | --- | --- |
| `server.listen_addr` | `:8080` | No | HTTP listen address for webhooks and health endpoints |
| `server.admin_token` | `""` | Recommended | Optional Bearer/Basic token protecting `/`, `/status`, `/metrics`, `/events`, and `/api/dry-run` |
| `gitea.base_url` | — | Yes | Base URL of your Gitea instance (e.g. `https://gitea.example.com`) |
| `gitea.token` | — | Yes | API token for the Gitea bot account |
| `gitea.webhook_secret` | `""` | Recommended | HMAC-SHA256 secret configured in Gitea webhooks |
| `gitea.bot_username` | `codespider` | No | Bot username used for `@mention` detection and self-loop prevention |
| `gitea.repos` | `[]` | No | Optional `owner/repo` list for periodic reconciliation (empty = auto-discover accessible repos) |
| `gitea.skip_draft_prs` | `true` | No | Skip pull requests marked as draft or titled `WIP:` / `[WIP]` |
| `gitea.ignore_bot_prs` | `true` | No | Skip pull requests authored by bots (`type: Bot` or `*[bot]`) |
| `gitea.sticky_summary` | `true` | No | Maintain a single updated walkthrough card per PR with a Mermaid change diagram |
| `gitea.require_collaborator_for_fix` | `true` | No | Require repository collaborator permission before executing `@codespider /fix` |
| `llm.base_url` | `https://api.openai.com/v1` | No | OpenAI-compatible base URL (vLLM, LiteLLM, OpenAI, OpenRouter, etc.) |
| `llm.api_key` | `""` | Recommended | Bearer token for the LLM endpoint |
| `llm.model` | `gpt-5` | No | Primary model identifier passed to `/chat/completions` |
| `llm.fast_model` | `""` | No | Optional fast/low-cost model for small PRs (<=50 lines), `/summary`, and `/ci` |
| `llm.timeout_seconds` | `120` | No | Per-request HTTP timeout for LLM calls |
| `llm.max_retries` | `2` | No | Max retries with exponential backoff on transient LLM errors (`429`, `5xx`) |
| `agent.max_steps` | `12` | No | Max tool-calling turns per PR run |
| `agent.max_tokens_per_run` | `32000` | No | Token budget cap per PR run |
| `agent.skills_dir` | `./skills` | No | Directory containing `<skill>/SKILL.md` folders |
| `agent.default_skills` | `[security, code-quality, testing]` | No | List of skills loaded (`security`, `code-quality`, `testing`, `performance`, `concurrency`, `chaos-resilience`) |
| `agent.enable_write` | `false` | No | Enables `write_file`, `edit_file`, and `commit_and_push` tools |
| `agent.adversarial_security` | `true` | No | Enables Blue-Team verification pass to refute false-positive inline findings before submission |
| `agent.enable_proof_of_bug` | `false` | No | Enables isolated `run_proof_test` (`go test -race`) verification inside PR worktrees |
| `alert.webhook_url` | `""` | No | Optional Slack/Discord/webhook URL notified on critical or secret-scan findings |
| `daemon.data_dir` | `./data` | No | Directory for git mirrors, worktrees, and `state.json` |
| `daemon.workers` | `2` | No | Number of concurrent PR review workers |
| `daemon.reconcile_interval_seconds` | `300` | No | Interval for periodic reconciliation |
| `daemon.log_level` | `info` | No | Log level (`debug`, `info`, `warn`, `error`) |

## Docker Compose ports and health checks

Both Compose files publish port `8080` on the host and forward it to port
`8080` in the container. If only the host port is in use, change the `ports`
entry in the Compose file you run to `"9090:8080"` and leave
`server.listen_addr: ":8080"` unchanged. Update any webhook URL that uses
the published host port. The container health check still uses port `8080`.

If you change the port **inside** the container, update `server.listen_addr`
in `codespider.yaml`, the container side of the port mapping, and the health
check URL together. For example, with `server.listen_addr: ":9090"`, set
these keys on the existing `codespider` service:

```yaml
ports:
  - "9090:9090"
healthcheck:
  test: ["CMD", "/app/codespider", "healthcheck", "-addr", "http://127.0.0.1:9090/healthz"]
```

Without the `healthcheck.test` override, the image probes
`http://127.0.0.1:8080/healthz` and reports an unhealthy container even if
CodeSpider is listening on the new port.

## Repository Configuration (`.codespider.yaml` & `AGENTS.md`)

CodeSpider automatically reads repository-level instructions and configuration from the checked-out PR worktree:

- **Instruction files** (injected into the review prompt):
  - `AGENTS.md`
  - `.gitea/review-instructions.md`
  - `.codespider/instructions.md`
- **`.codespider.yaml` (or `.codespider.yml`):**

```yaml
review:
  enabled: true
  min_severity: warning
  model: gpt-5
  auto_label: true
  auto_assign_reviewers: true
  adversarial_security: true
  skills:
    - security
    - code-quality
    - performance
    - chaos-resilience
  ignore_paths:
    - "*.lock"
    - "go.sum"
    - "vendor/**"
  instructions: |
    Verify context propagation on all database calls.
```
