# Configuration Reference

CodeSpider is configured via a YAML file (see [`codespider.example.yaml`](../codespider.example.yaml)).

Config file resolution order:
1. `-f <path>` CLI flag (`./codespider -f /etc/codespider/codespider.yaml`)
2. `CODESPIDER_CONFIG_PATH` environment variable
3. `./codespider.yaml` or `./codespider.yml` in the current working directory

String values support optional `${ENV_VAR}` expansion (for example, `api_key: "${LLM_API_KEY}"`).

Select the forge with `forge.provider`. Existing configurations that omit this
key continue to use Gitea. GitHub configurations need either a static
`github.token` or GitHub App credentials, plus the webhook secret. Forge tokens
are also used for HTTPS git operations.

## Daemon YAML Keys

| Key | Default | Required | Description |
| --- | --- | --- | --- |
| `server.listen_addr` | `:8080` | No | HTTP listen address for webhooks and health endpoints |
| `server.admin_token` | `""` | Recommended | Optional Bearer/Basic token protecting `/`, `/status`, `/metrics`, `/events`, and `/api/dry-run` |
| `forge.provider` | `gitea` | No | Forge backend: `gitea` or `github` |
| `forge.repos` | `[]` | No | Optional `owner/repo` allowlist for reconciliation; empty discovers repos accessible to the configured token |
| `forge.skip_draft_prs` | `true` | No | Skip draft and WIP pull requests |
| `forge.ignore_bot_prs` | `true` | No | Skip PRs authored by bots |
| `forge.sticky_summary` | `true` | No | Maintain one updated summary comment per PR |
| `forge.require_collaborator_for_fix` | `true` | No | Require collaborator permission before executing `/fix` |
| `gitea.base_url` | — | Required for Gitea | Base URL of your Gitea instance (e.g. `https://gitea.example.com`) |
| `gitea.token` | — | Required for Gitea | API token for the Gitea bot account |
| `gitea.webhook_secret` | `""` | Recommended | HMAC-SHA256 secret configured in Gitea webhooks |
| `gitea.bot_username` | `codespider` | No | Legacy Gitea alias for bot mention detection and self-loop prevention; use `github.bot_username` for GitHub |
| `gitea.repos` | `[]` | No | Legacy Gitea alias for the reconciliation allowlist; prefer `forge.repos` |
| `gitea.skip_draft_prs` | `true` | No | Legacy alias for `forge.skip_draft_prs` |
| `gitea.ignore_bot_prs` | `true` | No | Legacy alias for `forge.ignore_bot_prs` |
| `gitea.sticky_summary` | `true` | No | Legacy alias for `forge.sticky_summary` |
| `gitea.require_collaborator_for_fix` | `true` | No | Legacy alias for `forge.require_collaborator_for_fix` |
| `github.api_url` | `https://api.github.com` | No | GitHub REST API base URL; GitHub Enterprise Server commonly uses `https://HOST/api/v3` |
| `github.token` | — | Required unless GitHub App credentials are configured | Static GitHub token used for API requests and HTTPS git operations |
| `github.app_id` | — | No | GitHub App ID; configure together with installation ID and private key path to enable installation-token refresh |
| `github.installation_id` | — | No | GitHub App installation ID |
| `github.app_private_key_path` | — | No | Path to an RSA PEM private-key file mounted as a secret; installation tokens are refreshed automatically |
| `github.webhook_secret` | — | Required for GitHub | Secret configured on the GitHub webhook; invalid signatures are rejected |
| `github.bot_username` | `codespider` | No | Bot login used for mentions and self-loop prevention (GitHub App bots usually end in `[bot]`) |
| `github.repos` | `[]` | No | GitHub-specific reconciliation allowlist; `forge.repos` takes precedence when set |
| `llm.base_url` | `https://api.openai.com/v1` | No | OpenAI-compatible base URL (vLLM, LiteLLM, OpenAI, OpenRouter, etc.) |
| `llm.api_key` | `""` | Recommended | Bearer token for the LLM endpoint |
| `llm.model` | `gpt-5` | No | Primary model identifier passed to `/chat/completions` |
| `llm.fast_model` | `""` | No | Optional fast/low-cost model for small PRs (<=50 lines), `/summary`, and `/ci` |
| `llm.timeout_seconds` | `120` | No | Per-request HTTP timeout for LLM calls |
| `llm.max_retries` | `2` | No | Max retries with exponential backoff on transient LLM errors (`429`, `5xx`) |
| `llm.reasoning_effort` | `""` (omitted) | No | Sent as `reasoning_effort` on every chat request: `none`, `minimal`, `low`, `medium`, or `high`. Reasoning-capable models (for example Qwen via Ollama) can spend most of a review in hidden thinking tokens, so `none` or `low` helps on slow hardware. Providers that reject the field will return an error, so leave it empty unless your endpoint supports it. |
| `agent.max_steps` | `12` | No | Max tool-calling turns per PR run |
| `agent.job_timeout_seconds` | `300` | No | Wall-clock budget for one PR review job, 30 to 7200. Raise it for slow self-hosted models; it is separate from `llm.timeout_seconds`, which only bounds a single LLM request. |
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

The sticky summary comment (`forge.sticky_summary`) also lists a collapsible per-file `+/-` table and a heuristic 1-5 review-effort estimate derived from diff size.

With `auto_label: true`, CodeSpider attaches `size/XS`, `size/S`, `size/M`, `size/L` or `size/XL` from the diff size, plus `security` and `tests` when they apply. When the size bucket changes on a later review, the previous `size/*` label is removed so a PR carries one size label. Other labels, including `security`, are never removed automatically.

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
