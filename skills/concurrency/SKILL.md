---
name: concurrency
version: "2"
description: Concurrency and state-safety review skill targeting data races, early-return lock deadlocks, lock-across-I/O, goroutine leaks, and atomic state updates.
tags: [concurrency, race, deadlock, goroutines, atomicity]
tools: [get_pr_diff, read_file, search_code, run_proof_test]
---

Review the PR diff for **concurrency hazards, lifecycle leaks, and state corruption risks**.

## 1. Investigation Workflow
1. Identify goroutines, channels, `sync.Mutex`/`sync.RWMutex`, `sync.WaitGroup`, `atomic` values, and shared maps/slices in `get_pr_diff`.
2. Trace all callers, early returns, and error/cancellation paths with `read_file` and `search_code` to verify synchronization and shutdown behavior.
3. When isolated container execution is enabled, use `run_proof_test` to differentially test suspected races or deadlocks against base vs. head.

## 2. Concurrency & Lifecycle Checklist
- **Data Races (`critical`):** Unsynchronized concurrent reads/writes to maps, slices, or struct fields across goroutines, or returning internal mutable slices/maps without copying under lock.
- **Early-Return Deadlocks & Lock Ordering (`critical`):** `mu.Lock()` / `mu.RLock()` without `defer mu.Unlock()` where an early `return` leaves the mutex locked, inconsistent acquisition order across multiple mutexes, or calling `WaitGroup.Add` inside the spawned goroutine instead of before `go`.
- **Lock Contention Across I/O (`warning`):** Holding a mutex while making HTTP requests, DB queries, git subprocesses, or LLM calls.
- **Goroutine & Context Leaks (`warning` / `critical`):** Goroutines blocked on unbuffered/full channel sends or missing `select` on `ctx.Done()`, `time.Ticker` not stopped, or `context.WithCancel`/`WithTimeout` without `defer cancel()`.
- **TOCTOU & Non-Atomic Updates (`warning` / `critical`):** Check-then-act outside a lock, deleting map entries by key without generation/ID checks when newer jobs supersede older ones, non-atomic git pushes (missing `--atomic --force-with-lease`), or in-place file writes instead of temp-file + `os.Rename`.

## 3. Noise Suppression
- Only report concurrency issues where concurrent execution is actually reachable in the codebase.
