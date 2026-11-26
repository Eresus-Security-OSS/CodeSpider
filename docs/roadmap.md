# CodeSpider Engineering Roadmap & Module Specifications

This roadmap specifies the architecture, threat model, resource bounds, configuration, acceptance criteria, and limitations for CodeSpider's 17 intelligence modules and external integrations.

## Implemented vs. Next-Phase Modules

### Implemented Deterministic & Intelligence Modules
1. **Content-Addressed Code Knowledge Snapshot (`internal/codeintel`):** Solves incremental re-indexing cost across commits via SHA-256 AST caching; differentiates via zero-dep stdlib speed; bounded by file size and package scope; tested in `codeintel_test.go`.
2. **Cross-PR Semantic Conflict Detection (`internal/analysis/conflicts.go`):** Tracks open PR file/symbol footprints in-memory; low memory (<1 MiB); limitation: resets on daemon restart.
3. **Differential Verification Engine (`internal/sandbox/executor.go`):** Runs base vs. head `go test -race` inside `--network=none` containers; prevents host RCE; limitation: requires Docker/Podman when `sandbox.mode: container`.
4. **Security Invariant Tracking (`internal/analysis/invariants.go`):** Detects removed HMAC/auth/path guards and unsafe sinks deterministically.
5. **Incident-Aware Reviews (`internal/memory/store.go`):** Surfaces postmortem summaries only when PR paths match incident `path_prefix`.
6. **Behavioral Contract & API Compatibility Diff (`internal/analysis/contracts.go`):** Detects exported Go signature, `context.Context`, `error`, and JSON wire-tag breaks.
7. **Persistent Review Memory (`internal/memory/store.go`):** Stores authorized feedback, expiring rules, and policy simulation (`SimulatePolicy`).
8. **Dependency Change Intelligence (`internal/analysis/deps_iac.go`):** Flags local `replace` directives, pseudo-versions, and new `go.mod` modules.
9. **Architecture Fitness Functions (`internal/analysis/archfitness.go`):** Enforces `forbid_imports` and import-cycle detection.
10. **Database Migration & Rollback Safety (`internal/analysis/migrations.go`):** Flags destructive DDL, lock hazards, and missing `.down.sql` rollbacks.
11. **Test Impact Analysis (`internal/analysis/conflicts.go`):** Traverses `ReverseCallers` (3 hops) to surface impacted `Test*` targets.
12. **Infrastructure-as-Code Review (`internal/analysis/deps_iac.go`):** Audits `Dockerfile`, Compose, and K8s YAML diffs.
13. **Incremental Review Cache (`internal/analysis/pipeline.go`):** Memoizes deterministic reports by `(repo, baseSHA, headSHA, diffHash, policyHash)`.
14. **Offline Deterministic & Shadow/Dry-Run Replay (`--offline`, `--dry-run`, `/api/dry-run`):** Replays historical PRs without Gitea mutations.

### Planned Extensions (9-Point Specifications)

#### 1. Mutation-Based Test Review
- **Problem:** PRs with high line coverage can still have weak assertions that miss logic mutations.
- **Differentiation:** Runs targeted AST mutations (flipping conditionals/boundary operators) on changed Go functions inside the container sandbox.
- **Architecture:** `internal/sandbox/mutator.go` generates mutated copies of changed functions and invokes `sandbox.Executor.RunGoTest`.
- **Threat Model:** Executes untrusted code only inside `--network=none --cap-drop=ALL` containers; never on host.
- **Resource Requirements:** Capped at `max_mutations_per_pr: 10`, `30s` per run, `512m` RAM.
- **Configuration:** `agent.enable_mutation_testing: false`.
- **Acceptance Criteria:** Survives only when tests fail to detect injected bug; marks `inconclusive` if sandbox unavailable.
- **Known Limitations:** Go-only initially; expensive on slow integration test suites.
- **Integration Tests:** Mutate `<` to `<=` on a boundary helper and verify surviving mutant warning.

#### 2. Temporal Persistent Graph & External Integrations (Phase 8)
- **GitHub / GitLab Providers (`internal/provider`):** Implement `ForgeProvider` for GitHub App / GitLab webhooks; keep Gitea/Forgejo primary.
- **MCP Server (`cmd/codespider mcp`):** Expose `search_org_repos`, `git_forensics`, and `codeintel` read-only tools over stdio/JSON-RPC for IDE agents, enforcing `policy.CapReadWorktree`.
- **LSP & Multi-Language Analyzers:** Optional out-of-process LSP/tree-sitter sidecar with strict timeout and `io.LimitReader` bounds.
- **Eresus Guard & Eresus Workbench:** Export SARIF 2.1.0 (`--sarif`) and webhook alerts (`alert.webhook_url`) into Eresus security pipelines without coupling core daemon state.
