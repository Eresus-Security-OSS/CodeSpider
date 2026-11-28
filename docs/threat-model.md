# CodeSpider Threat Model

## 1. Trust Boundaries

| Boundary | Untrusted Inputs | Trusted Inputs |
| :--- | :--- | :--- |
| **Webhook Ingress** | HTTP body, headers (until HMAC-SHA256 verified) | Selected provider webhook secret, `server.admin_token` |
| **GitHub Provider** | HTTP body, `X-Hub-Signature-256`, configured token or App private key, and API base URL | HMAC verified before parsing; static or short-lived installation token is held in memory for API/HTTPS git auth; App private key is read from the configured secret file; API URL must be HTTPS. |
| **Pull Request Content** | PR title/body, diff, source code, `.codespider.yaml` on PR head, PR/review comments, commit messages, tool outputs | `codespider.yaml` daemon config, base-branch `.codespider.yaml` (`refs/heads/<base>`), `skills/` on daemon host |
| **Code Execution** | Any Go test, `init()`, or build script inside PR worktree | Container runtime (`--network=none`, `--cap-drop=ALL`, `--read-only`) |
| **Review Memory** | PR comments from external/fork contributors | Collaborator/admin feedback via authenticated API or collaborator-gated commands |

## 2. Mitigated Threats

1. **Prompt Injection -> Tool Privilege Escalation:**
   - *Mitigation:* Untrusted PR text/comments/repo instructions are wrapped in sanitized `<untrusted_*>` delimiters (`policy.WrapUntrustedInput`). Tool authorization is enforced in Go (`policy.CheckToolAllowed`) before any tool handler runs; LLMs cannot invoke `commit_and_push`, `search_org_repos`, or `run_proof_test` without the required `Capability`.
2. **Host RCE via Untrusted PR Tests:**
   - *Mitigation:* Host-side `go test` execution is removed. `run_proof_test` requires `sandbox.mode: container` and `!IsFork`, running inside a network-disabled, read-only, non-privileged container with memory/CPU/PID caps.
3. **Policy Bypass via PR-Head `.codespider.yaml`:**
   - *Mitigation:* Worker reads trusted policy from the base branch mirror (`ReadMirrorFile`) rather than the PR head worktree.
4. **Cross-Repository Exfiltration from Fork PRs:**
   - *Mitigation:* Fork PRs (`IsFork == true`) are stripped of `CapCrossRepoRead`, `CapWriteWorktree`, `CapPushCommits`, `CapIsolatedExec`, and `CapMutateMemory`. `search_org_repos` additionally enforces owner/repo allowlists.
5. **Credential Exfiltration via `CloneURL` or Error Logs:**
   - *Mitigation:* `workspace.Manager.WithAllowedOrigin(cfg.GiteaBaseURL)` refuses HTTP(S) clone/push URLs whose `scheme://host` does not match the configured Gitea origin. Git and LLM secrets are redacted from all error strings.
6. **Stale Commit / TOCTOU Race on Review or Push:**
   - *Mitigation:* `VerifyHeadUnchanged` checks remote PR `Head.SHA` before posting reviews, and `CommitAndPush` checks `git ls-remote` against `expectedHeadSHA` before pushing.
7. **Unauthorized Memory Poisoning:**
   - *Mitigation:* `memory.Store.RecordFeedback` and `UpsertRule` require explicit authorization (`ErrUnauthorizedMemoryMutation`), blocking untrusted PR comments from mutating org-wide rules.
8. **Admin Token Leakage in URLs:**
   - *Mitigation:* Dashboard & SSE (`/events`) authenticate via `HttpOnly; SameSite=Strict` HMAC-signed session cookie (`POST /api/session`) rather than query-string tokens.
