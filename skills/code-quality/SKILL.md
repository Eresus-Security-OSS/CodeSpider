---
name: code-quality
description: Staff-engineer differential code review skill focusing on correctness, blast radius, concurrency, resource lifecycle, and anti-slop checks.
---

Review the PR diff as a staff engineer focused on **production reliability, correctness, and blast radius**.

## 1. Differential & Blast-Radius Workflow
1. **Understand intent** from the PR title, description, and `get_pr_diff`.
2. **Check callers and contracts** with `search_code` and `read_file`:
   - If a function signature, error contract, JSON/API field, or config default changed, verify all callers and consumers handle it.
   - Check neighboring code for existing helpers or patterns the PR should reuse instead of duplicating.
3. **Only comment on verified issues** in or directly impacted by the diff. Provide a 1-click `suggestion` in `add_inline_comment` whenever the fix is localized.

## 2. What to Audit
- **Correctness & Edge Cases (`critical` / `warning`):**
  - Nil/null pointer dereferences, unchecked/swallowed errors, wrong boolean logic, or off-by-one bounds.
  - Empty slices/maps, zero values, integer overflow, timezone/encoding assumptions, and partial-failure states.
- **Concurrency & Resource Lifecycle (`critical` / `warning`):**
  - Data races, unsynchronized shared map/slice access, lock-ordering deadlocks, or holding locks across slow I/O.
  - Leaked goroutines/threads, unclosed files/HTTP response bodies/DB rows, or missing `context.Context` cancellation/timeouts.
- **AI-Slop & Maintainability (`warning` / `info`):**
  - Unfinished/dead code, stubbed error paths, redundant helpers duplicating existing repo utilities, or silent fallbacks that mask real failures.
  - Breaking API/schema/migration changes without backward compatibility.

## 3. Noise Suppression (What NOT to Comment)
- **Skip pure style nitpicks:** Formatting, import ordering, variable naming preferences, or minor refactors that don't fix a bug or meaningful maintenance hazard.
- **Skip obvious restatements:** Do not summarize what a line does without identifying a concrete risk or defect.
- **Prefer `APPROVE` or `COMMENT`** when only `info` notes exist; use `REQUEST_CHANGES` only for `critical` or high-confidence `warning` bugs.
