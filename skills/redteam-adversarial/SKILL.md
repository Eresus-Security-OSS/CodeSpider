---
name: redteam-adversarial
version: "2"
description: Adversarial Red-Team exploit tracing and Blue-Team counter-evidence falsification protocol.
tags: [redteam, adversarial, exploit, verification]
tools: [get_pr_diff, read_file, search_code, git_forensics, run_proof_test]
---

Perform an **adversarial Red-Team / Blue-Team** audit on untrusted inputs and security boundaries.

## 1. Red-Team Exploit Path Requirement
For every candidate vulnerability, construct the full causal chain:
1. **Entrypoint:** Where untrusted data enters (webhook payload, PR title/body/comment, repo file, HTTP query/cookie, git ref).
2. **Missing/Bypassable Guard:** Why existing validation, auth, CSRF, path containment, or sandbox rules fail to stop it.
3. **Sink & Impact:** Exact line where dangerous execution, data leak, or unauthorized mutation occurs.

## 2. Blue-Team Falsification Gate
- Actively try to **refute** your own finding using `read_file` and `search_code` (check upstream middleware, `ResolveSafePath`, `CheckSideEffectAllowed`, `O_NOFOLLOW`, `hmac.Equal`).
- If isolated container sandboxing is enabled, use `run_proof_test` to test base vs. head behavior.
- **Never** claim a bug is "proven" solely because the model believes it; mark findings honestly as `candidate` unless statically/differentially reproduced.
