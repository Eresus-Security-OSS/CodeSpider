# ADR-0001: Hybrid Deterministic + Agentic Code Intelligence Architecture

- **Status:** Accepted
- **Context:** Pure LLM code review loops suffer from position drift (invalid diff line numbers), high false-positive rates on mitigated patterns, and the **Context Degradation Paradox** (SWE-PRBench, `arxiv.org/abs/2603.26130`), where dumping large raw ASTs or whole files degrades contextual recall.
- **Decision:** CodeSpider uses a **hybrid deterministic-first + bounded-agentic** architecture built solely on the Go standard library (`go/token`, `go/parser`, `go/ast`, `go/types`):
  1. **Deterministic Core (`internal/codeintel`, `internal/analysis`, `internal/security`):** Indexes changed/base Go packages with a content-addressed `sha256` AST cache, computes behavioral contract diffs, import cycles, security invariant regressions, migration/rollback hazards, dependency/IaC risks, and intermediate-commit secrets **before** calling any LLM.
  2. **Compact Evidence Brief:** Injects a structured `<1,200`-token summary of statically supported facts into the agent prompt rather than dumping full ASTs.
  3. **Offline Mode (`--offline`):** Allows deterministic-only PR reviews and benchmarks with zero LLM calls.
- **Consequences:** Higher precision, deterministic baseline metrics, lower token cost, and zero external Go module dependencies. Non-Go languages currently rely on diff/regex/IaC/migration analyzers and LLM inspection until optional external LSP/analyzer adapters are added.
