# ADR-0002: Capability-Based Authorization & Container-Only Execution Isolation

- **Status:** Accepted
- **Context:** Phase 0 audit revealed that executing `go test` in a PR worktree on the daemon host (`run_proof_test`), trusting PR-head `.codespider.yaml`, allowing unpinned `CloneURL` credentials, and allowing fork PRs to query `search_org_repos` exposed the daemon to RCE, policy bypass, and cross-repository secret/code exfiltration.
- **Decision:**
  1. **Fail-Closed Capability Model (`internal/policy`):** Every tool requires an explicit `Capability` evaluated deterministically from verified PR metadata (`IsFork`, `IsCollaborator`, `DryRun`, `SandboxMode`, allowlists). LLM outputs never grant or override capabilities.
  2. **Trusted Policy Sourcing:** `.codespider.yaml` enforcement settings (`enabled`, `ignore_paths`, `min_severity`, `forbid_imports`, `adversarial_security`) are loaded from the repository's **base branch** in the bare mirror when available, never from an untrusted PR head.
  3. **Container-Only Sandbox (`internal/sandbox`):** Untrusted PR code execution is disabled by default (`sandbox.mode: disabled`) and permitted only inside an isolated container (`--network=none --read-only --cap-drop=ALL --security-opt=no-new-privileges --pids-limit=64`) for non-fork PRs.
- **Consequences:** Eliminates host RCE and fork-PR cross-repo exfiltration while preserving explicit `inconclusive` evidence states when container execution is unavailable.
