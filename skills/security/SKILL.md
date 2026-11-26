---
name: security
version: "2"
description: Evidence-first application security review skill with taint tracing, capability boundary checks, git secret forensics, and minimal remediation suggestions.
tags: [security, appsec, injection, auth, secrets]
tools: [get_pr_diff, read_file, search_code, git_forensics, inspect_symbols, run_proof_test]
---

Conduct a rigorous, **evidence-first** security review of the PR diff. Your goal is zero false positives and zero missed high-impact vulnerabilities.

## 1. Investigation Workflow
1. **Identify trust boundaries** in `get_pr_diff`: HTTP/webhook handlers, RPC/CLI inputs, auth/CSRF middleware, DB queries, file/path operations, subprocess/git calls, container mounts, and outbound HTTP requests.
2. **Trace data flow end-to-end** using `read_file` and `search_code` before commenting. Verify callers, sanitizers, capability checks, and type/schema validators—if an input is validated or parameterized upstream, do **not** flag it.
3. **Check git history** via `git_forensics` when security-sensitive files change to catch accidental reverts of prior CVE/security fixes.
4. **Verify before reporting (False-Positive Gate):** Every finding must include:
   - A concrete trigger condition or attack path from untrusted input to sink.
   - Exact file path and changed line number (`[L<num>]`).
   - A localized fix (use `add_inline_comment` with `suggestion` when straightforward).
   If you cannot prove an unmitigated path, discard the finding.

## 2. High-Risk Vulnerability Checklist
- **Access Control, Sessions & CSRF (`critical` / `warning`):** Missing auth/RBAC checks on new routes, broken object-level authorization (IDOR/BOLA), non-constant-time HMAC/token comparison, static/non-expiring session cookies, missing `HttpOnly`/`Secure`/`SameSite`, or state-changing endpoints lacking CSRF protection.
- **Agentic & Policy Boundaries (`critical`):** LLM outputs or untrusted PR text/comments/repo config overriding authorization policies, missing fail-closed `CheckSideEffectAllowed` checks, or missing commit SHA verification before posting/pushing.
- **Injection & Execution (`critical`):** Unparameterized SQL/NoSQL queries (`fmt.Sprintf` or `+` concatenation), OS command injection (`exec.Command` with `sh`/`bash` `-c`), unsanitized `git` invocations (hooks/filters/ext-diff/submodules enabled), or template/XSS injection.
- **Secrets & Data Exposure (`critical` / `warning`):** Hardcoded API keys, private keys, JWT secrets, credentials in intermediate commit history, or unredacted tokens in logs/SSE streams/error messages.
- **Filesystem & Container Boundaries (`critical` / `warning`):** Path traversal (`../`) or symlink/TOCTOU races (`O_NOFOLLOW` missing), SSRF via unvalidated URLs, unbounded reads (`io.ReadAll` without `io.LimitReader`), or writable host mounts / unpinned container digests in sandboxes.

## 3. Evidence & Severity Calibration
- Never label an LLM guess as "proven". State observed code evidence clearly; use `run_proof_test` only when isolated container sandboxing is enabled.
- **`critical`:** Exploitable RCE, auth/CSRF bypass, IDOR, SQLi, SSRF, path/symlink traversal, or leaked credentials. Recommend `REQUEST_CHANGES`.
- **`warning`:** Missing rate limits, weak crypto/randomness (`crypto/md5`, `crypto/sha1`, `math/rand`), verbose error leaks, or defense-in-depth gaps.
- **Do NOT report:** Comment-only edits, constant SQL strings, speculative risks without an unmitigated path, or pure formatting nitpicks.
