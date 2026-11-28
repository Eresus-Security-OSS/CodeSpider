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
| `daemon.update_check_hours` | `0` (off) | No | Hours between checks for a newer release tag on `api.github.com`. `0` disables it, so the daemon makes no outbound update calls. When enabled, a newer release is logged once and exposed under `update` in `/status`. Needs a release or image build that stamps a version (see below); development builds are never compared. |
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
  path_instructions:
    - "internal/db/**: Every transaction must have a deferred Rollback."
    - "*.sql: Flag destructive DDL that has no rollback script."
  base_branches:
    - main
    - "release/*"
  ignore_title_keywords: [WIP, "[skip review]"]
  title_pattern: "^(feat|fix|docs|chore)(\(.+\))?: .+"
  require_description: true
  max_changed_lines: 800
  instructions: |
    Verify context propagation on all database calls.
```

`path_instructions` takes a block list of `"<glob>: <instruction>"` items (up to 32, each truncated at 1 KiB). When a changed file matches the glob, the instruction is appended to the review prompt together with the matching paths. Globs follow the same rules as `ignore_paths`. Only the block-list form is supported, and the key is read from the PR head like `instructions`, so it guides the model but cannot disable review gates.

The sticky summary comment (`gitea.sticky_summary`) also lists a collapsible per-file `+/-` table and a heuristic 1-5 review-effort estimate derived from diff size.

Automatic-review gating and pre-merge checks:

- `base_branches` limits automatic reviews to PRs targeting a matching branch (`path.Match` globs, so `release/*` matches `release/1.2` but not `release/1.2/hotfix`). `ignore_title_keywords` skips PRs whose title contains a keyword (case-insensitive). A skipped PR gets a `success` commit status that names the reason. `/review` and `/redteam` always run.
- `title_pattern` (RE2 regex, max 256 characters), `require_description`, and `max_changed_lines` add an advisory **Pre-merge checks** table to the sticky summary. They never change commit status.
- All five keys are policy: when the base branch has a `.codespider.yaml`, they are read from that file only, so a PR head cannot widen `base_branches`, add skip keywords, or weaken checks. The value is taken literally (no YAML escape processing), so write regex backslashes once.

### Fork pull requests

Pull requests from a fork are untrusted, so nothing is read from the fork's head for them. The review uses the **base branch** versions of `.codespider.yaml`, `AGENTS.md`, `.gitea/review-instructions.md`, `.codespider/instructions.md` (including `instructions` and `path_instructions`), and `CODEOWNERS` for reviewer assignment, read from the cached mirror. The repository keeps its review rules, while a fork author cannot disable gates, inject prompt instructions, or choose reviewers. If the base branch has none of these files, the fork PR is reviewed with defaults and no extra instructions. The mirror is refreshed on each checkout, so a base-branch change applies from the next review.

## Updating CodeSpider

CodeSpider never replaces its own binary. It ships as a container image (`ghcr.io/eresus-security-oss/codespider`, built on `v*` tags) and from source, so updating means pulling the new image or rebuilding.

- `codespider version` prints the build version. `codespider update` asks `api.github.com` for the highest stable `vMAJOR.MINOR.PATCH` tag and prints the matching `docker pull`, `docker compose pull && docker compose up -d`, or `git checkout` command when a newer one exists. Pre-release tags are ignored.
- Release images are stamped with the tag via the `VERSION` build argument (`-X main.version`). A source build can stamp one with `go build -ldflags "-X main.version=v1.2.3" ./cmd/codespider`; an unstamped build reports `dev` and the check makes no network request.
- Set `daemon.update_check_hours` to have the daemon check periodically. A failed re-check keeps an update that an earlier check already found.
