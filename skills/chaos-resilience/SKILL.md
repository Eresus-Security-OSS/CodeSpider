---
name: chaos-resilience
version: "2"
description: Distributed-systems failure-mode review skill tracing timeouts, stale-state races, SQL rollback safety, partial failures, and retry idempotency.
tags: [resilience, timeouts, idempotency, transactions, recovery]
tools: [get_pr_diff, read_file, search_code, git_forensics]
---

Audit the PR diff for **failure-mode cascades and partial-failure hazards** under real-world outages.

## 1. Failure-Mode Investigation Workflow
1. Locate outbound network calls, subprocess invocations, file/DB writes, transaction blocks, and webhook/queue handlers in `get_pr_diff`.
2. Trace callers with `search_code` and `read_file` to check what happens when a dependency stalls, times out, returns a partial error, or delivers duplicate events.

## 2. Resilience & Chaos Checklist
- **Stalled Dependencies & Missing Deadlines (`critical` / `warning`):** Outbound HTTP/DB/git/subprocess calls using `context.Background()` instead of the request/job `ctx`, or missing client/request timeouts.
- **Database Transaction Rollback Safety (`warning`):** `db.Begin` / `BeginTx` without `defer tx.Rollback()`, leaving locks held if an error or panic occurs before `tx.Commit()`.
- **Lock Contention Across Slow I/O (`critical` / `warning`):** Acquiring a `sync.Mutex` or shared lock and holding it while performing network requests, disk clones, or LLM calls.
- **Partial Failures & Non-Atomic State (`warning`):** Multi-step mutations where step 2 fails after step 1 succeeded, leaving persisted state (`state.json`, DB rows, git worktrees) inconsistent or leaked.
- **Retry, Stale-SHA & Webhook Idempotency (`warning`):** Event handlers or retry loops that duplicate side effects when delivered twice, or review/fix pipelines that publish against a stale PR head SHA after newer commits arrive.

## 3. Noise Suppression
- Only report concrete failure paths reachable from the changed code; provide localized fixes when possible.
