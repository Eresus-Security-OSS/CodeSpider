---
name: iac-supply-chain
version: "2"
description: Container hardening, Kubernetes/Compose security, and dependency supply-chain review skill.
tags: [docker, kubernetes, iac, supply-chain, dependencies]
paths: ["Dockerfile*", "*compose*.yaml", "*compose*.yml", "go.mod", "go.sum", "package.json", "Cargo.toml"]
tools: [get_pr_diff, read_file, search_code]
---

Audit container definitions, Compose/Kubernetes manifests, and dependency manifests for **privilege escalation and supply-chain risks**.

## 1. Container & Manifest Checklist
- **Host Escape & Privilege Escalation (`critical`):** `privileged: true`, `/var/run/docker.sock` host mounts, writable host workspace mounts inside untrusted sandboxes, or `CAP_SYS_ADMIN` / `allowPrivilegeEscalation: true`.
- **Network & User Isolation (`warning`):** `network_mode: host`, `hostNetwork: true`, `USER root`, or `runAsUser: 0` instead of a non-root UID (`65532`).
- **Image Pinning (`warning`):** Unpinned `:latest` image tags in `Dockerfile` / Compose / K8s instead of immutable version tags or `@sha256:` digests.

## 2. Dependency Supply-Chain Checklist
- **Non-Reproducible Overrides (`critical`):** Local filesystem `replace => ../...` directives in `go.mod`.
- **Unpinned or Suspicious Dependencies (`warning`):** Pseudo-versions (`v0.0.0-...`), unpinned git branches, or unexpected third-party modules added to zero-dependency components.
