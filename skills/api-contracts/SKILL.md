---
name: api-contracts
version: "2"
description: Backward-compatibility and cross-repo contract review skill for Go interfaces, exported signatures, JSON wire tags, and polyglot APIs.
tags: [api, contracts, compatibility, breaking-change]
tools: [get_pr_diff, inspect_symbols, search_code, search_org_repos, read_file]
---

Audit the PR diff for **breaking public API, serialization, and behavioral contract changes** across callers and downstream repositories.

## 1. Contract Investigation Workflow
1. Inspect exported functions, methods, interfaces, structs, and HTTP/RPC routes changed in `get_pr_diff` using `inspect_symbols` (works across Go, Python, TypeScript/JavaScript, and Rust).
2. Search internal callers via `search_code` and cross-repo consumers via `search_org_repos` (when permitted by policy).

## 2. Breaking-Change Checklist
- **Exported Symbol & Interface Breaks (`critical`):** Removed exported functions/types with remaining callers, or added/modified methods on exported Go interfaces (breaks all downstream implementers).
- **Signature & Behavioral Contract Drift (`critical` / `warning`):** Dropped `context.Context` parameter, dropped `error` return, altered generic type constraints (`any` -> `comparable`), or silently changed error/nil semantics.
- **Wire & Serialization Compatibility (`warning` / `critical`):** Renamed/removed `json:` / `yaml:` / `protobuf` struct tags, changed field types, or altered HTTP route paths/status codes without versioning.

## 3. Noise Suppression
- Do not flag unexported internal helper renames or signature changes when all callers in the PR are updated consistently.
