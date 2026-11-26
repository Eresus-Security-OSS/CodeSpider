---
name: security
description: Evidence-first application security review skill with taint tracing, false-positive verification, and minimal remediation suggestions.
---

Conduct a rigorous, **evidence-first** security review of the PR diff. Your goal is zero false positives and zero missed high-impact vulnerabilities.

## 1. Investigation Workflow
1. **Identify trust boundaries** in `get_pr_diff`: HTTP/webhook handlers, RPC/CLI inputs, auth middleware, DB queries, file/path operations, subprocess calls, and outbound HTTP requests.
2. **Trace data flow end-to-end** using `read_file` and `search_code` before commenting. Check callers, middleware, and type/schema validators—if an input is validated or parameterized upstream, do **not** flag it.
3. **Verify before reporting (False-Positive Gate):** Every finding must have:
   - A concrete, realistic trigger condition or attack path from entrypoint to sink.
   - Exact file path and changed line number.
   - A localized fix (use `add_inline_comment` with `suggestion` when straightforward).
   If you cannot prove an unmitigated path, discard the finding.

## 2. High-Risk Vulnerability Checklist
- **Access Control & Auth (CRITICAL/WARNING):** Missing auth/session checks on new routes, broken object-level authorization (IDOR/BOLA—querying by user-supplied ID without tenant/owner scope), privilege escalation, or weak signature checks (non-constant-time HMAC/token compare, `alg=none` JWT).
- **Injection & Execution (CRITICAL):** Unparameterized SQL/NoSQL/LDAP queries, OS command injection (`exec.Command`, `sh -c`, `subprocess` with shell/user args), template/XSS injection, or unsafe deserialization.
- **Secrets & Data Exposure (CRITICAL/WARNING):** Hardcoded API keys, private keys, JWT secrets, default credentials, or logging/returning raw tokens, PII, or internal stack traces to clients.
- **Filesystem & Network Boundaries (CRITICAL/WARNING):** Path traversal (`../`) without canonicalization/containment checks, SSRF via unvalidated user URLs, or unbounded reads (`io.ReadAll` without `LimitReader`).
- **Supply Chain & Agentic Guardrails (WARNING):** Newly added dependencies with suspicious/typo-squatted names, or LLM/agent prompts that mix untrusted user input into system/tool instructions without isolation.

## 3. Severity Calibration & Noise Suppression
- **`critical`:** Exploitable RCE, auth bypass, IDOR, SQLi, SSRF, path traversal, or leaked credentials. Recommend `REQUEST_CHANGES`.
- **`warning`:** Missing rate limits, weak crypto/randomness, verbose error leaks, or defense-in-depth gaps with plausible impact.
- **`info`:** Minor hardening improvements only when directly relevant to changed code.
- **Do NOT report:** Speculative "could be unsafe if..." without an unmitigated path, pre-existing unchanged code (unless the PR newly exposes it), or formatting/style preferences.
