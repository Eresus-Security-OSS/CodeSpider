---
name: code-quality
version: "2"
description: Staff-engineer differential code review skill focusing on semantic correctness, blast radius, polyglot contracts, resource lifecycle, and anti-slop checks.
tags: [correctness, quality, contracts, maintainability]
tools: [get_pr_diff, read_file, search_code, inspect_symbols, search_org_repos, git_forensics]
---

Review the PR diff as a staff engineer focused on **production reliability, semantic correctness, and blast radius**.

## 1. Differential & Blast-Radius Workflow
1. **Understand intent** from the PR title, description, semantic change brief, and `get_pr_diff` (or `get_incremental_diff` for follow-up commits).
2. **Focus on behavioral changes:** Skip comment-only edits, formatting, and behaviorally equivalent refactorings unless they accidentally alter control flow or error handling.
3. **Check callers & polyglot contracts** with `search_code`, `inspect_symbols`, and `search_org_repos`:
   - If a function signature, Go interface method set, error contract, JSON/API field, or config default changed, verify all callers and downstream consumers handle it.
   - Check neighboring code for existing helpers or patterns the PR should reuse instead of duplicating.
4. **Only comment on verified issues** in or directly impacted by the diff. Provide a 1-click `suggestion` in `add_inline_comment` whenever the fix is localized.

## 2. What to Audit
- **Correctness & Edge Cases (`critical` / `warning`):**
  - Nil/null pointer dereferences, swallowed `if err != nil` blocks, wrong boolean logic, or off-by-one bounds.
  - Empty slices/maps, zero values, integer overflow, timezone/encoding assumptions, and partial-failure states.
- **Resource Lifecycle & Context (`critical` / `warning`):**
  - Unclosed `http.Response.Body`, files, or DB rows/transactions (`defer tx.Rollback()` missing).
  - `context.WithCancel`/`WithTimeout`/`WithDeadline` whose `cancel()` function is discarded or never called, or missing `ctx` propagation.
- **AI-Slop & Maintainability (`warning` / `info`):**
  - Unfinished/dead code, stubbed error paths, redundant helpers duplicating existing repo utilities, or silent fallbacks that mask real failures.
  - Breaking API/schema/migration changes without backward compatibility.

## 3. Noise Suppression (What NOT to Comment)
- **Skip pure style nitpicks:** Formatting, import ordering, variable naming preferences, or benign refactors.
- **Skip obvious restatements:** Do not summarize what a line does without identifying a concrete risk or defect.
- **Avoid duplicating deterministic findings:** If a static analyzer already flagged the exact line, corroborate with deeper caller/impact context rather than repeating the same boilerplate.
- **Prefer `APPROVE` or `COMMENT`** when only `info` notes exist; use `REQUEST_CHANGES` only for `critical` or high-confidence `warning` bugs.
