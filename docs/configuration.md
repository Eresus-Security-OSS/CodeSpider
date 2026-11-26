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
| `gitea.base_url` | — | Yes | Base URL of your Gitea instance (e.g. `https://gitea.example.com`) |
| `gitea.token` | — | Yes | API token for the Gitea bot account |
| `gitea.webhook_secret` | `""` | Recommended | HMAC-SHA256 secret configured in Gitea webhooks |
| `gitea.bot_username` | `codespider` | No | Bot username used for `@mention` detection and self-loop prevention |
| `gitea.skip_draft_prs` | `true` | No | Skip pull requests marked as draft or titled `WIP:` / `[WIP]` |
| `gitea.ignore_bot_prs` | `true` | No | Skip pull requests authored by bots (`type: Bot` or `*[bot]`) |
| `llm.base_url` | `https://api.openai.com/v1` | No | OpenAI-compatible base URL (vLLM, LiteLLM, OpenAI, OpenRouter, etc.) |
| `llm.api_key` | `""` | Recommended | Bearer token for the LLM endpoint |
| `llm.model` | `gpt-5` | No | Model identifier passed to `/chat/completions` |
| `llm.timeout_seconds` | `120` | No | Per-request HTTP timeout for LLM calls |
| `agent.max_steps` | `12` | No | Max tool-calling turns per PR run |
| `agent.max_tokens_per_run` | `32000` | No | Token budget cap per PR run |
| `agent.skills_dir` | `./skills` | No | Directory containing `<skill>/SKILL.md` folders |
| `agent.default_skills` | `[security, code-quality, testing]` | No | List of skills loaded into the agent |
| `agent.enable_write` | `false` | No | Enables `write_file`, `edit_file`, and `commit_and_push` tools |
| `daemon.data_dir` | `./data` | No | Directory for git mirrors, worktrees, and `state.json` |
| `daemon.workers` | `2` | No | Number of concurrent PR review workers |
| `daemon.reconcile_interval_seconds` | `300` | No | Interval for periodic reconciliation |
| `daemon.log_level` | `info` | No | Log level (`debug`, `info`, `warn`, `error`) |

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
  ignore_paths:
    - "*.lock"
    - "go.sum"
    - "vendor/**"
  instructions: |
    Verify context propagation on all database calls.
```
