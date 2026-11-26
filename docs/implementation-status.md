# Implementation Status

This document records the exact, verified implementation state of every CodeSpider subsystem without placeholders or inflated claims.

| Phase / Module | Status | Package / Entrypoint | Verification | Known Limitations |
| :--- | :--- | :--- | :--- | :--- |
| **Phase 0: Audit & Fixes** | Implemented | `docs/research/phase0-independent-audit.md` | Verified by unit + integration tests | — |
| **Phase 1: Competitive Research** | Implemented | `docs/research/competitor-matrix.md` | Grounded web research + SPDX audit | — |
| **Phase 2: Security & Policy** | Implemented | `internal/policy`, `internal/audit`, `internal/sandbox`, `internal/skills`, `internal/workspace` | Unit + race + integration tests | Container sandbox requires `docker` or `podman` daemon when `sandbox.mode: container` |
| **Phase 3: Go Code Intelligence** | Implemented | `internal/codeintel` | AST + `go/types` + SHA-256 cache tests | Non-stdlib `go/types` packages fall back to AST call/symbol extraction; non-Go uses diff/regex analyzers |
| **Phase 4: Deterministic Suite** | Implemented | `internal/analysis` | Unit + benchmark + integration tests | Cross-PR conflict tracker is in-memory per daemon lifecycle |
| **Phase 5: Evidence States** | Implemented | `internal/evidence`, `internal/agent/adversarial.go` | Unit tests | Differential container reproduction requires `sandbox.mode: container` |
| **Phase 6: Review Memory** | Implemented | `internal/memory`, `/api/memory` | Unit tests + HTTP API | Semantic embedding retrieval is not included (uses deterministic fingerprints, patterns, and path prefixes) |
| **Phase 7: Benchmark Harness** | Implemented | `internal/benchmark`, `testdata/benchmarks/local_suite.jsonl`, `codespider bench` | Unit test + CLI run | Offline baseline measured; live multi-model ReviewBench/SWE-PRBench runs depend on external API keys |
| **Phase 8: SARIF & Provider** | Implemented | `internal/sarif`, `internal/provider` | Unit tests | Gitea/Forgejo validated; GitHub/GitLab/MCP/LSP/Eresus adapters specified in `docs/roadmap.md` |
| **Phase 9: Real Git/Gitea E2E & Fuzz** | Implemented | `internal/testgitea`, `internal/worker/integration_test.go`, `fuzz_test.go` | Race + integration + fuzz tests | Requires `git-http-backend` on PATH for Smart-HTTP CGI tests |
