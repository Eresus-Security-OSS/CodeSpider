package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Eresus-Security-OSS/CodeSpider/internal/audit"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/config"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/events"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/memory"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/metrics"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/orggraph"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/store"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/worker"
)

func TestHTTPEndpoints(t *testing.T) {
	cfg := config.Default()
	cfg.LLMModel = "gpt-5"
	cfg.Workers = 2

	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	mem, err := memory.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	mc := metrics.NewCollector()
	broker := events.NewBroker(10)
	broker.Publish(events.Event{Type: "run_started", PRKey: "acme/api#1", Message: "boot"})

	pool := worker.NewPool(worker.Config{Workers: 1, Store: st, Metrics: mc, Events: broker, Memory: mem})
	auditLog := audit.NewLogger(t.TempDir())
	og, _ := orggraph.Open("")
	handler := buildHTTPHandler(cfg, pool, st, mc, broker, mem, auditLog, og)

	// /healthz
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK || rec.Body.String() != "ok" {
		t.Fatalf("unexpected /healthz: %d %q", rec.Code, rec.Body.String())
	}

	// /status
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/status", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected /status code: %d", rec.Code)
	}
	var statusPayload map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &statusPayload); err != nil {
		t.Fatalf("invalid /status JSON: %v", err)
	}
	if statusPayload["model"] != "gpt-5" {
		t.Fatalf("unexpected model in /status: %v", statusPayload["model"])
	}

	// /metrics
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "codespider_active_jobs") {
		t.Fatalf("unexpected /metrics response: %d %s", rec.Code, rec.Body.String())
	}

	// /events?once=1 replays buffered SSE events
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/events?once=1", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "data: ") || !strings.Contains(rec.Body.String(), "acme/api#1") {
		t.Fatalf("unexpected /events response: %d %s", rec.Code, rec.Body.String())
	}

	// /webhook fails closed when RequireSecret=true and secret is empty
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader([]byte(`{}`))))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected fail-closed 401 on /webhook without secret, got %d", rec.Code)
	}

	// Unknown path returns 404
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/does-not-exist", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for unknown path, got %d", rec.Code)
	}
}

func TestSessionCookieAdminAuthAndMemoryAPI(t *testing.T) {
	cfg := config.Default()
	cfg.AdminToken = "top-admin-secret"
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	mem, err := memory.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	mc := metrics.NewCollector()
	pool := worker.NewPool(worker.Config{Workers: 1, Store: st, Metrics: mc, Memory: mem})
	handler := buildHTTPHandler(cfg, pool, st, mc, events.NewBroker(10), mem, audit.NewLogger(t.TempDir()), nil)

	// /status requires admin token (query string ?token= must NOT work)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/status?token=top-admin-secret", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected query-string token to be rejected, got %d", rec.Code)
	}

	// Login via POST /api/session sets HttpOnly cookie and returns CSRF token
	loginRec := httptest.NewRecorder()
	handler.ServeHTTP(loginRec, httptest.NewRequest(http.MethodPost, "/api/session", strings.NewReader(`{"token":"top-admin-secret"}`)))
	if loginRec.Code != http.StatusOK || len(loginRec.Result().Cookies()) == 0 {
		t.Fatalf("expected session cookie on login, code=%d", loginRec.Code)
	}
	var sessionResp struct {
		Authenticated bool   `json:"authenticated"`
		CSRFToken     string `json:"csrf_token"`
	}
	if err := json.Unmarshal(loginRec.Body.Bytes(), &sessionResp); err != nil || !sessionResp.Authenticated || sessionResp.CSRFToken == "" {
		t.Fatalf("expected csrf_token in session response, got %s (err=%v)", loginRec.Body.String(), err)
	}
	cookie := loginRec.Result().Cookies()[0]

	// /status succeeds with session cookie
	req := httptest.NewRequest(http.MethodGet, "/status", nil)
	req.AddCookie(cookie)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 with session cookie, got %d", rec.Code)
	}

	// Cookie-authenticated POST without X-CSRF-Token must fail with 403
	csrfFailReq := httptest.NewRequest(http.MethodPost, "/api/memory", strings.NewReader(`{"kind":"rule","rule":{"id":"r1","instruction":"x"}}`))
	csrfFailReq.AddCookie(cookie)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, csrfFailReq)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 when CSRF token missing on cookie POST, got %d", rec.Code)
	}

	// Cookie-authenticated POST with malformed Origin must fail closed with 403
	badOriginReq := httptest.NewRequest(http.MethodPost, "/api/memory", strings.NewReader(`{"kind":"rule","rule":{"id":"r2","instruction":"y"}}`))
	badOriginReq.AddCookie(cookie)
	badOriginReq.Header.Set("X-CSRF-Token", sessionResp.CSRFToken)
	badOriginReq.Header.Set("Origin", "://malformed-origin")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, badOriginReq)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 when Origin header is malformed, got %d", rec.Code)
	}

	// Cookie-authenticated POST with valid X-CSRF-Token succeeds
	csrfOKReq := httptest.NewRequest(http.MethodPost, "/api/memory", strings.NewReader(`{"kind":"rule","rule":{"id":"r1","instruction":"x"}}`))
	csrfOKReq.AddCookie(cookie)
	csrfOKReq.Header.Set("X-CSRF-Token", sessionResp.CSRFToken)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, csrfOKReq)
	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201 with valid CSRF token, got %d (%s)", rec.Code, rec.Body.String())
	}

	// Operations APIs (/api/languages, /api/reviews, /api/audit) require auth and return JSON
	for _, ep := range []string{"/api/languages", "/api/reviews", "/api/audit"} {
		unauthRec := httptest.NewRecorder()
		handler.ServeHTTP(unauthRec, httptest.NewRequest(http.MethodGet, ep, nil))
		if unauthRec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 on %s without auth, got %d", ep, unauthRec.Code)
		}
		authReq := httptest.NewRequest(http.MethodGet, ep, nil)
		authReq.AddCookie(cookie)
		authRec := httptest.NewRecorder()
		handler.ServeHTTP(authRec, authReq)
		if authRec.Code != http.StatusOK {
			t.Fatalf("expected 200 on %s with cookie, got %d", ep, authRec.Code)
		}
	}

	o, r, pr, err := parseReviewTarget("", 0, []string{"acme/api#42"})
	if err != nil || o != "acme" || r != "api" || pr != 42 {
		t.Fatalf("unexpected parseReviewTarget: %s/%s#%d err=%v", o, r, pr, err)
	}
}
