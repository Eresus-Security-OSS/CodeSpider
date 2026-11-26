---
name: performance
version: "2"
description: Evidence-first performance review skill targeting N+1 I/O, loop-defer leaks, unbounded memory growth, hot-path allocations, and lock contention.
tags: [performance, memory, io, latency]
tools: [get_pr_diff, read_file, search_code]
---

Audit the PR diff for **concrete, high-impact performance regressions** without micro-optimizing cold paths.

## 1. Investigation Workflow
1. Inspect loops, request handlers, AST/file walkers, and data pipelines in `get_pr_diff`.
2. Use `read_file` and `search_code` to check call frequency (request hot path vs. startup/CLI) and dataset bounds before reporting.

## 2. High-Impact Performance Checklist
- **N+1 Queries & Loop I/O (`warning` / `critical`):** Database queries, HTTP calls, redundant file parses, or `git`/subprocess invocations executed per item inside a loop without batching, caching, or bounded concurrency.
- **Loop-Scoped `defer` & Descriptor Exhaustion (`warning`):** Calling `defer f.Close()` or `defer resp.Body.Close()` inside a `for`/`range` loop instead of closing in a helper function, pinning file descriptors until the outer function returns.
- **Unbounded Buffering & Memory Growth (`warning` / `critical`):** Reading entire streams/responses into memory without size caps (`io.LimitReader`), unbounded slices/maps/queues that grow with untrusted input, or missing pagination limits.
- **Hot-Path Allocation & Compilation Churn (`warning`):** Compiling regular expressions (`regexp.Compile`), building reflection schemas, or opening new HTTP clients/DB pools inside per-request or per-item loops.
- **Lock Contention (`warning`):** Holding mutexes across slow network/disk I/O or external calls, blocking concurrent workers.

## 3. Noise Suppression
- Do **not** flag micro-optimizations on one-time initialization code or small bounded collections.
- Provide a concrete, localized `suggestion` when hoisting an invariant or adding a bound is straightforward.
