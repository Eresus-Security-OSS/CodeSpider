# Configuration Reference

CodeSpider is configured via environment variables (see [`.env.example`](../.env.example)).

| Variable | Default | Required | Description |
| --- | --- | --- | --- |
| `CODESPIDER_LISTEN_ADDR` | `:8080` | No | HTTP listen address for webhooks and health endpoints |
| `GITEA_BASE_URL` | — | Yes | Base URL of your Gitea instance (e.g. `https://gitea.example.com`) |
| `GITEA_TOKEN` | — | Yes | API token for the Gitea bot account |
| `GITEA_WEBHOOK_SECRET` | `""` | Recommended | HMAC-SHA256 secret configured in Gitea webhooks |
| `GITEA_BOT_USERNAME` | `codespider` | No | Bot username used for `@mention` detection and self-loop prevention |
| `SKIP_DRAFT_PRS` | `true` | No | Skip pull requests marked as draft or titled `WIP:` / `[WIP]` |
| `IGNORE_BOT_PRS` | `true` | No | Skip pull requests authored by bots (`type: Bot` or `*[bot]`) |
| `LLM_BASE_URL` | `https://api.openai.com/v1` | No | OpenAI-compatible base URL (vLLM, LiteLLM, OpenAI, OpenRouter, etc.) |
| `LLM_API_KEY` | `""` | Recommended | Bearer token for the LLM endpoint |
| `LLM_MODEL` | `gpt-5` | No | Model identifier passed to `/chat/completions` |
| `LLM_TIMEOUT_SECONDS` | `120` | No | Per-request HTTP timeout for LLM calls |
| `AGENT_MAX_STEPS` | `12` | No | Max tool-calling turns per PR run |
| `AGENT_MAX_TOKENS_PER_RUN` | `32000` | No | Token budget cap per PR run |
| `AGENT_SKILLS_DIR` | `./skills` | No | Directory containing `<skill>/SKILL.md` folders |
| `AGENT_DEFAULT_SKILLS` | `security,code-quality,testing` | No | Comma-separated list of skills loaded into the agent |
| `AGENT_ENABLE_WRITE` | `false` | No | Enables `write_file`, `edit_file`, and `commit_and_push` tools |
| `DATA_DIR` | `./data` | No | Directory for git mirrors, worktrees, and `state.json` |
| `WORKERS` | `2` | No | Number of concurrent PR review workers |
| `LOG_LEVEL` | `info` | No | Log level (`debug`, `info`, `warn`, `error`) |

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
