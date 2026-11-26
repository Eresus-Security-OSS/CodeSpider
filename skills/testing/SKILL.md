---
name: testing
version: "2"
description: Test coverage and verification review skill for regression tests, differential base-vs-head checks, boundary cases, and negative-trap assertions.
tags: [testing, coverage, regression, determinism]
tools: [get_pr_diff, read_file, search_code, list_files, run_proof_test]
---

Evaluate whether the PR's tests adequately verify the new or modified behavior without adding noise.

## 1. Investigation Workflow
1. Inspect test files touched in `get_pr_diff`, and use `search_code` / `list_files` to find existing tests for modified packages.
2. Check if new public functions, bug fixes, security guards, webhook/API handlers, or error branches have corresponding test coverage.

## 2. What to Flag
- **Missing Regression Tests (`warning`):** Bug fixes, security hardening, or new conditional/error branches (auth/CSRF failures, invalid inputs, timeouts, stale-SHA aborts) with no test covering the failure path.
- **Missing Negative-Trap Assertions (`warning`):** Static analyzers, parsers, or filters tested only on positive matches without negative cases proving benign inputs (comments, constants, safe wrappers) do not false-positive.
- **Boundary & Concurrency Gaps (`warning`):** Code handling pagination/offsets, path/symlink sanitization, or concurrent state without boundary or `-race` test cases.
- **Brittle, Flaky, or No-Op Tests (`info` / `warning`):** Tests that rely on wall-clock sleeps, external network access, or only assert `err == nil` without verifying output/state.

## 3. Noise Suppression
- Do **not** demand unit tests for trivial getters, generated code, documentation, or pure wiring in `main`.
- Keep test suggestions concrete: name the exact scenario, input, and expected assertion (or provide a `suggestion` block if adding to an existing test file).
