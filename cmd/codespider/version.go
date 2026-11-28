package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"strings"
	"time"

	"github.com/Eresus-Security-OSS/CodeSpider/internal/update"
)

// version is stamped at build time: go build -ldflags "-X main.version=v1.2.3".
// Unstamped builds report "dev" and are never compared against releases.
var version = "dev"

// buildVersion returns the stamped version, falling back to the module version embedded
// by `go install ...@vX.Y.Z` when no ldflags were used.
func buildVersion() string {
	if version != "dev" {
		return version
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		if v := info.Main.Version; v != "" && v != "(devel)" {
			return v
		}
	}
	return version
}

func runVersionCLI(w io.Writer) int {
	fmt.Fprintf(w, "codespider %s\n", buildVersion())
	return 0
}

// runUpdateCLI reports whether a newer release exists and how to install it. It never
// replaces the running binary: CodeSpider ships as a container image and from source.
func runUpdateCLI(args []string, w io.Writer, checker *update.Checker) int {
	fs := flag.NewFlagSet("update", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(w, "usage: codespider update")
		return 2
	}
	if checker == nil {
		checker = update.NewChecker()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	current := buildVersion()
	st, err := checker.Check(ctx, current)
	switch {
	case errors.Is(err, update.ErrDevBuild):
		fmt.Fprintf(w, "codespider %s is a development build, so it cannot be compared with releases.\n", current)
		fmt.Fprintln(w, "Build with -ldflags \"-X main.version=vX.Y.Z\" or use a release image to enable update checks.")
		return 0
	case err != nil:
		fmt.Fprintf(os.Stderr, "update check failed: %v\n", err)
		return 1
	case !st.UpdateAvailable:
		fmt.Fprintf(w, "codespider %s is up to date (latest release: %s).\n", st.Current, st.Latest)
		return 0
	}
	fmt.Fprintf(w, "A newer release is available: %s (running %s).\n\n", st.Latest, st.Current)
	fmt.Fprintln(w, "Update with one of:")
	fmt.Fprintf(w, "  docker pull ghcr.io/eresus-security-oss/codespider:%s\n", strings.TrimPrefix(st.Latest, "v"))
	fmt.Fprintln(w, "  docker compose pull && docker compose up -d")
	fmt.Fprintf(w, "  git fetch --tags && git checkout %s && go build -o codespider ./cmd/codespider\n", st.Latest)
	return 0
}
