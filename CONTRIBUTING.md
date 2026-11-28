# Contributing to CodeSpider

Thanks for helping improve CodeSpider. Bug reports, focused fixes, documentation updates, and review skills are welcome.

## Before you start

- Read the repository [AGENTS.md](AGENTS.md) for architecture, security, and verification requirements.
- For larger changes, open an issue or discussion first to agree on the approach.
- Keep the project dependency-free: use the Go standard library unless a new dependency has been explicitly approved.

## Development setup

Use the Go version declared in [`go.mod`](go.mod). Copy the example configuration if you need to run the daemon locally:

```sh
cp codespider.example.yaml codespider.yaml
# Edit codespider.yaml with local Gitea and LLM settings.
```

Do not commit `codespider.yaml` or credentials. The local configuration is gitignored.

## Making changes

- Keep changes focused and follow the existing package boundaries and Go style. Format Go code with `gofmt`.
- Preserve security boundaries: validate paths through `workspace.ResolveSafePath` (and `resolveWritablePath` for writes), verify webhook signatures, bound and close HTTP bodies, propagate contexts, and protect shared state.
- Keep tests offline and deterministic. Use `httptest` and temporary directories where appropriate; cover failure and security cases as well as success paths.
- Update relevant documentation and `codespider.example.yaml` when changing configuration or user-visible behavior.

## Verification

Before submitting a change, run the project checks:

```sh
go build ./...
go vet ./...
go test -race -v ./...
```

Docker or Compose changes should also pass:

```sh
docker compose -f docker-compose.yaml config -q
docker compose -f docker-compose.dev.yaml config -q
```

## Pull requests

Please include a clear summary of the problem and solution, link any relevant issue, and note the checks you ran. Include tests for behavior changes and screenshots or example output when they help explain a user-facing change. Keep each pull request focused and call out any known limitations.

## Security issues

Please do not report exploitable vulnerabilities in a public issue. Follow the private reporting process described by the project hosting organization, or contact its maintainers directly.

## License

By contributing, you agree that your contributions are provided under the project’s [Apache License 2.0](LICENSE).
