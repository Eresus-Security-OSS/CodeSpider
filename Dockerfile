# syntax=docker/dockerfile:1

FROM golang:1.26-trixie AS builder

WORKDIR /src

# Download Go modules first for better layer & BuildKit cache reuse
COPY go.mod go.sum* ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY . .

# Build static binary using Go module + build caches. VERSION is stamped into the binary for update checks.
ARG VERSION=dev
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/codespider ./cmd/codespider

# Stage git binary, HTTPS remote helpers, and their Debian 13 shared libraries for distroless
RUN set -eux; \
    mkdir -p /git-rootfs/usr/bin /git-rootfs/usr/lib/git-core /git-rootfs/app/data; \
    cp /usr/bin/git /git-rootfs/usr/bin/git; \
    for helper in git-remote-http git-remote-https git-upload-pack git-receive-pack; do \
        if [ -e "/usr/lib/git-core/$helper" ]; then \
            cp -a "/usr/lib/git-core/$helper" /git-rootfs/usr/lib/git-core/; \
        fi; \
    done; \
    for bin in /usr/bin/git /usr/lib/git-core/git-remote-http; do \
        ldd "$bin" | awk '/=> \// {print $3} /^\// {print $1}' | while read -r lib; do \
            if [ -f "$lib" ]; then \
                dest="$lib"; \
                case "$dest" in /lib/*|/lib64/*) dest="/usr$dest" ;; esac; \
                mkdir -p "/git-rootfs$(dirname "$dest")"; \
                cp -L -n "$lib" "/git-rootfs$dest"; \
            fi; \
        done; \
    done; \
    chown -R 65532:65532 /git-rootfs/app

FROM gcr.io/distroless/base-debian13:nonroot

WORKDIR /app

COPY --from=builder /git-rootfs/usr/ /usr/
COPY --from=builder --chown=65532:65532 /git-rootfs/app/ /app/
COPY --from=builder /out/codespider /app/codespider
COPY --chown=65532:65532 skills /app/skills

ENV CODESPIDER_CONFIG_PATH=/app/codespider.yaml

EXPOSE 8080

USER nonroot:nonroot

HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD ["/app/codespider", "healthcheck"]

ENTRYPOINT ["/app/codespider"]
CMD ["-f", "/app/codespider.yaml"]
