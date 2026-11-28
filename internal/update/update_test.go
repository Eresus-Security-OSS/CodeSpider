package update

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func tagServer(t *testing.T, body string, status int, hits *atomic.Int32) *Checker {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path != "/repos/acme/app/tags" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return &Checker{APIBase: srv.URL, Repo: "acme/app", HTTP: srv.Client()}
}

func TestParseVersionRejectsPrereleaseAndJunk(t *testing.T) {
	for _, ok := range []string{"v1.2.3", "1.2.3", " v10.0.1 "} {
		if _, valid := ParseVersion(ok); !valid {
			t.Errorf("%q should parse", ok)
		}
	}
	for _, bad := range []string{"", "dev", "main", "v1.2", "v1.2.3-rc1", "v1.2.3+meta", "v1.2.x", "v99999999999999999999.0.0"} {
		if _, valid := ParseVersion(bad); valid {
			t.Errorf("%q must not parse", bad)
		}
	}
	a, _ := ParseVersion("v1.9.0")
	b, _ := ParseVersion("v1.10.0")
	if !a.Less(b) || b.Less(a) {
		t.Fatal("version ordering must be numeric, not lexical")
	}
}

func TestCheckPicksHighestStableTag(t *testing.T) {
	var hits atomic.Int32
	c := tagServer(t, `[{"name":"v1.0.1"},{"name":"v1.10.0"},{"name":"v1.9.0"},{"name":"v2.0.0-rc1"},{"name":"nightly"}]`, 200, &hits)

	st, err := c.Check(context.Background(), "v1.9.0")
	if err != nil {
		t.Fatal(err)
	}
	if st.Latest != "v1.10.0" || !st.UpdateAvailable {
		t.Fatalf("expected v1.10.0 to be offered, got %+v", st)
	}

	st, err = c.Check(context.Background(), "1.10.0")
	if err != nil || st.UpdateAvailable {
		t.Fatalf("current == latest must not offer an update, got %+v err=%v", st, err)
	}

	st, _ = c.Check(context.Background(), "v3.0.0")
	if st.UpdateAvailable {
		t.Fatal("a build newer than every tag must not downgrade")
	}
}

func TestCheckDevBuildMakesNoRequest(t *testing.T) {
	var hits atomic.Int32
	c := tagServer(t, `[]`, 200, &hits)
	for _, cur := range []string{"dev", "main", "v1.2.3-rc1"} {
		if _, err := c.Check(context.Background(), cur); !errors.Is(err, ErrDevBuild) {
			t.Errorf("%q: expected ErrDevBuild, got %v", cur, err)
		}
	}
	if hits.Load() != 0 {
		t.Fatalf("dev builds must not call the network, got %d requests", hits.Load())
	}
}

func TestCheckSurfacesServerAndPayloadErrors(t *testing.T) {
	var hits atomic.Int32
	for name, tc := range map[string]struct {
		body   string
		status int
	}{
		"http error": {`{"message":"rate limited"}`, 403},
		"bad json":   {`not json`, 200},
		"no stable":  {`[{"name":"v1.0.0-beta"}]`, 200},
	} {
		c := tagServer(t, tc.body, tc.status, &hits)
		st, err := c.Check(context.Background(), "v1.0.0")
		if err == nil || st.UpdateAvailable || st.Error == "" {
			t.Errorf("%s: expected an error status, got %+v err=%v", name, st, err)
		}
	}
}

func TestMonitorAnnouncesEachVersionOnce(t *testing.T) {
	var hits atomic.Int32
	c := tagServer(t, `[{"name":"v1.1.0"}]`, 200, &hits)
	m := NewMonitor(c, "v1.0.0")

	var announced atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		m.Run(ctx, 10*time.Millisecond, func(Status) { announced.Add(1) }, nil)
		close(done)
	}()
	deadline := time.After(2 * time.Second)
	for hits.Load() < 3 {
		select {
		case <-deadline:
			t.Fatal("monitor did not re-check")
		case <-time.After(5 * time.Millisecond):
		}
	}
	cancel()
	<-done

	if announced.Load() != 1 {
		t.Fatalf("expected exactly one announcement across %d checks, got %d", hits.Load(), announced.Load())
	}
	if st := m.Status(); !st.UpdateAvailable || st.Latest != "v1.1.0" {
		t.Fatalf("unexpected stored status: %+v", st)
	}

	var nilMon *Monitor
	if nilMon.Status().UpdateAvailable {
		t.Fatal("nil monitor must report no update")
	}
}

func TestMonitorKeepsFoundUpdateAcrossTransientFailure(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			_, _ = w.Write([]byte(`[{"name":"v1.1.0"}]`))
			return
		}
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	m := NewMonitor(&Checker{APIBase: srv.URL, Repo: "acme/app", HTTP: srv.Client()}, "v1.0.0")

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	var errCount atomic.Int32
	go func() {
		m.Run(ctx, 10*time.Millisecond, nil, func(error) { errCount.Add(1) })
		close(done)
	}()
	deadline := time.After(2 * time.Second)
	for errCount.Load() < 1 {
		select {
		case <-deadline:
			t.Fatal("expected a failed re-check")
		case <-time.After(5 * time.Millisecond):
		}
	}
	cancel()
	<-done

	st := m.Status()
	if !st.UpdateAvailable || st.Latest != "v1.1.0" || st.Error == "" {
		t.Fatalf("a failed re-check must keep the known update and record the error, got %+v", st)
	}
}
