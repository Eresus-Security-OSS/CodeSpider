package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Eresus-Security-OSS/CodeSpider/internal/update"
)

func withVersion(t *testing.T, v string) {
	t.Helper()
	old := version
	version = v
	t.Cleanup(func() { version = old })
}

func TestRunUpdateCLIReportsAvailableUpToDateAndDev(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[{"name":"v1.2.0"},{"name":"v1.1.0"}]`))
	}))
	defer srv.Close()
	checker := &update.Checker{APIBase: srv.URL, Repo: "acme/app", HTTP: srv.Client()}

	withVersion(t, "v1.1.0")
	var out bytes.Buffer
	if code := runUpdateCLI(nil, &out, checker); code != 0 {
		t.Fatalf("exit %d", code)
	}
	for _, want := range []string{"v1.2.0", "docker pull ghcr.io/eresus-security-oss/codespider:1.2.0", "git checkout v1.2.0"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("update output missing %q:\n%s", want, out.String())
		}
	}

	withVersion(t, "v1.2.0")
	out.Reset()
	if code := runUpdateCLI(nil, &out, checker); code != 0 || !strings.Contains(out.String(), "up to date") {
		t.Fatalf("expected up-to-date message, code=%d out=%s", code, out.String())
	}

	withVersion(t, "dev")
	out.Reset()
	if code := runUpdateCLI(nil, &out, checker); code != 0 || !strings.Contains(out.String(), "development build") {
		t.Fatalf("expected development-build message, code=%d out=%s", code, out.String())
	}
}

func TestRunUpdateCLIFailsOnUnreachableServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusBadGateway)
	}))
	defer srv.Close()
	withVersion(t, "v1.0.0")
	checker := &update.Checker{APIBase: srv.URL, Repo: "acme/app", HTTP: srv.Client()}
	if code := runUpdateCLI(nil, &bytes.Buffer{}, checker); code != 1 {
		t.Fatalf("expected exit 1 on check failure, got %d", code)
	}
}

func TestRunVersionCLIPrintsStampedVersion(t *testing.T) {
	withVersion(t, "v1.0.0")
	var out bytes.Buffer
	if runVersionCLI(&out) != 0 || strings.TrimSpace(out.String()) != "codespider v1.0.0" {
		t.Fatalf("unexpected version output %q", out.String())
	}
}
