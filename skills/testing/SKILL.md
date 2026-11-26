---
name: testing
description: Test coverage and verification review skill for catching untested error paths, boundary cases, and brittle assertions.
---

Evaluate whether the PR's tests adequately verify the new or modified behavior without adding noise.

## 1. Investigation Workflow
1. Inspect test files touched in `get_pr_diff`, and use `search_code` / `read_file` to find existing tests for modified packages.
2. Check if new public functions, bug fixes, webhook/API handlers, or error branches have corresponding test coverage.

## 2. What to Flag
- **Missing Regression Tests (`warning`):** Bug fixes or new conditional/error branches (auth failures, invalid inputs, timeouts, edge cases) with no test covering the failure path.
- **Boundary & Concurrency Gaps (`warning`):** Code handling pagination/offsets, path sanitization, parsing, or concurrent state without boundary or race-safe test cases.
- **Brittle or No-Op Tests (`info` / `warning`):** Tests that only assert no-error without checking returned state/output, or tests heavily coupled to internal implementation details that will break on benign refactors.

## 3. Noise Suppression
- Do **not** demand unit tests for trivial getters, generated code, documentation, or pure wiring changes in `main`.
- Keep test suggestions concrete: name the exact scenario, input, and expected assertion (or provide a `suggestion` block if adding to an existing test file).
