# Production Validation & Verification Status

This document records **only directly observed** verification results on this host and explicitly marks blocked checks where required external runtimes are absent.

## Verified on This Host

1. **Build & Static Checks**
   - `gofmt -w .`
   - `go build ./...` (zero external dependencies in `go.mod`)
   - `go vet ./...`
2. **Full Unit, Race & Integration Suite**
   - `go test -race -v ./...` (run with loopback socket permission on macOS for `httptest.NewServer` and `git-http-backend` Smart-HTTP integration tests).
   - Includes:
     - `internal/worker/integration_test.go`: End-to-end Smart-HTTP Git clone/fetch/commit/push against simulated Gitea API (`internal/testgitea`).
     - `internal/sandbox/lab_test.go`: Differential Proof-of-Bug pipeline verified with a mock container runtime validating `:ro` workspace mounts, compile-error -> `inconclusive` classification, flake repeat, and candidate patch verification.
     - `cmd/codespider/main_test.go`: Expiring session cookies, CSRF enforcement on cookie `POST`s, and authenticated operations APIs.
3. **Fuzz Testing**
   - `go test -fuzz=FuzzScanPatches -fuzztime=3s ./internal/security`
   - `go test -fuzz=FuzzParseConfigYAML -fuzztime=3s ./internal/config`
4. **Split Benchmark Evaluation (95% Wilson CIs, Zero Cross-Split Leakage)**
   - `go run ./cmd/codespider bench --split all` across `testdata/benchmarks/{dev,validation,holdout}.jsonl` (60 cases total, including negative-trap cases for comment guard edits, constant SQL queries, `io.LimitReader`, `defer Close()`, `defer Unlock()`, `defer cancel()`, `defer tx.Rollback()`).

## Blocked on This Host (Not Production Validated)

| Check | Status | Blocker on Current Host | How to Validate in CI / Staging |
| --- | --- | --- | --- |
| Live Container Sandbox (`docker` / `podman`) | **Blocked** | Docker daemon socket `/var/run/docker.sock` is not running on this macOS host. | Start Docker/Podman, pull a digest-pinned `golang@sha256:...` image, set `sandbox.mode: container` and `sandbox.require_image_digest: true`, and run `codespider review`. |
| Live Gitea Server Integration | **Blocked** | `gitea` binary / `docker compose` runtime is not running on this host. | Run `docker compose -f docker-compose.dev.yaml up -d`, create a disposable repo + webhook, and test `/review`, `/fix`, and stale-SHA superseding against live Gitea. |
