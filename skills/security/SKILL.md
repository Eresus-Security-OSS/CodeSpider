---
name: security
description: Security-focused PR review checklist for injection, auth, secrets, SSRF, path traversal, and unsafe deserialization.
---

When reviewing code, actively check for security vulnerabilities and trace untrusted input from entrypoints to sinks using `read_file` and `search_code`:

1. **Injection & Command Execution**
   - SQL/NoSQL/LDAP injection via string concatenation or unparameterized queries.
   - OS command injection (`exec.Command`, `subprocess`, `sh -c`) with user-controlled arguments.
   - Template injection or XSS in HTML/JS rendering.

2. **Authentication & Authorization**
   - Missing auth middleware, broken object-level authorization (IDOR), or privilege escalation.
   - Weak signature/token verification (e.g., non-constant-time comparisons, `alg=none` JWTs, missing webhook HMAC checks).

3. **Secrets & Sensitive Data**
   - Hardcoded API keys, tokens, private keys, or credentials.
   - Logging secrets, PII, or full authorization headers.

4. **Filesystem & Network Boundaries**
   - Path traversal (`../`) when joining user input to file paths without canonicalization.
   - SSRF via unvalidated URLs passed to HTTP clients.
   - Unbounded request body reads (`io.ReadAll` without `LimitReader`) or zip-bomb/DoS vectors.

Report only verified issues with concrete attack paths and minimal remediation.
