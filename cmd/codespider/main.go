// Command codespider runs the 24/7 agentic Gitea PR review daemon.
package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/Eresus-Security-OSS/CodeSpider/internal/agent"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/audit"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/config"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/events"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/evidence"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/gitea"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/lang"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/llm"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/memory"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/metrics"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/opsintel"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/orggraph"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/sandbox"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/security"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/skills"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/store"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/worker"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/workspace"
)

const sessionCookieName = "cs_session"

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "review":
			os.Exit(runReviewCLI(os.Args[2:]))
		case "bench":
			os.Exit(runBenchCLI(os.Args[2:]))
		case "healthcheck":
			os.Exit(runHealthcheckCLI(os.Args[2:]))
		}
	}

	configFlag := flag.String("f", "", "Path to codespider.yaml config file (overrides CODESPIDER_CONFIG_PATH)")
	flag.Parse()

	cfgPath := config.ResolvePath(*configFlag)
	cfg, err := config.LoadFromFile(cfgPath)
	if err != nil {
		slog.Error("configuration error", "path", cfgPath, "err", err)
		os.Exit(1)
	}

	logger := newLogger(cfg.LogLevel)
	slog.SetDefault(logger)

	loadedSkills, err := skills.LoadSelected(cfg.AgentSkillsDir, cfg.AgentDefaultSkills)
	if err != nil {
		logger.Warn("failed to load some skills, continuing without them", "err", err)
	} else {
		logger.Info("loaded agent skills", "count", len(loadedSkills), "skills", cfg.AgentDefaultSkills)
	}

	st, err := store.Open(cfg.DataDir)
	if err != nil {
		logger.Error("failed to open state store", "err", err)
		os.Exit(1)
	}
	memStore, err := memory.Open(cfg.DataDir)
	if err != nil {
		logger.Error("failed to open memory store", "err", err)
		os.Exit(1)
	}
	orgGraph, err := orggraph.Open(cfg.DataDir)
	if err != nil {
		logger.Warn("failed to open orggraph store, using in-memory graph", "err", err)
		orgGraph, _ = orggraph.Open("")
	}
	opsCorrelator, err := opsintel.Load(cfg.OpsTelemetryPath, cfg.AllowLLMTelemetrySharing)
	if err != nil {
		logger.Warn("failed to load ops telemetry snapshot", "err", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	metricsCollector := metrics.NewCollector()
	eventBroker := events.NewBroker(100).WithRedactor(func(msg string) string {
		return security.RedactText(msg, cfg.GiteaToken, cfg.LLMAPIKey, cfg.GiteaWebhookSecret, cfg.AdminToken)
	})
	auditLog := audit.NewLogger(cfg.DataDir)
	giteaClient := gitea.NewClient(cfg.GiteaBaseURL, cfg.GiteaToken)
	wsManager := workspace.NewManager(cfg.DataDir, cfg.GiteaToken).WithAllowedOrigin(cfg.GiteaBaseURL)
	wsManager.CleanupStaleWorktrees(ctx)

	llmClient := llm.NewClient(cfg.LLMBaseURL, cfg.LLMAPIKey, cfg.LLMModel, cfg.LLMTimeout).
		WithRetry(cfg.LLMMaxRetries, time.Second)

	runner := agent.NewRunner(llmClient, agent.Options{
		MaxSteps:            cfg.AgentMaxSteps,
		MaxTokens:           cfg.AgentMaxTokens,
		EnableWrite:         cfg.AgentEnableWrite,
		AdversarialSecurity: cfg.AgentAdversarialSecurity,
		FastModel:           cfg.LLMFastModel,
		SkillsDir:           cfg.AgentSkillsDir,
		Skills:              loadedSkills,
		Events:              eventBroker,
		Logger:              logger,
	})

	pool := worker.NewPool(worker.Config{
		Workers:                   cfg.Workers,
		QueueSize:                 128,
		EnableWrite:               cfg.AgentEnableWrite,
		EnableProofOfBug:          cfg.AgentEnableProofOfBug,
		AuthorName:                cfg.GiteaBotUsername,
		SkipDrafts:                cfg.SkipDraftPRs,
		IgnoreBots:                cfg.IgnoreBotPRs,
		StickySummary:             cfg.StickySummary,
		RequireCollaboratorForFix: cfg.RequireCollaboratorForFix,
		AllowSameOwnerCrossRepo:   cfg.AllowSameOwnerCrossRepo,
		CrossRepoAllowlist:        cfg.CrossRepoAllowlist,
		SandboxMode:               cfg.SandboxMode,
		AlertWebhookURL:           cfg.AlertWebhookURL,
		Gitea:                     giteaClient,
		Workspace:                 wsManager,
		Agent:                     runner,
		Store:                     st,
		Metrics:                   metricsCollector,
		Events:                    eventBroker,
		Audit:                     auditLog,
		Memory:                    memStore,
		OrgGraph:                  orgGraph,
		OpsIntel:                  opsCorrelator,
		Sandbox: sandbox.NewExecutor(sandbox.Config{
			Mode:               cfg.SandboxMode,
			Runtime:            cfg.SandboxRuntime,
			Image:              cfg.SandboxImage,
			RequireImageDigest: cfg.SandboxRequireImageDigest,
		}),
		Logger: logger,
	})

	var cfgPtr atomic.Pointer[config.Config]
	cfgPtr.Store(&cfg)

	pool.Start(ctx)
	pool.StartReconciler(ctx, cfg.ReconcileInterval, cfg.GiteaRepos)

	// SIGHUP hot-reloads skills, budgets, routing, and runtime flags atomically without dropping active PR jobs.
	sighupCh := make(chan os.Signal, 1)
	signal.Notify(sighupCh, syscall.SIGHUP)
	defer signal.Stop(sighupCh)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-sighupCh:
				newCfg, loadErr := config.LoadFromFile(cfgPath)
				if loadErr != nil {
					logger.Warn("SIGHUP config reload failed, keeping existing config", "err", loadErr)
					auditLog.Log(audit.Event{Action: "config_reload", Decision: "deny", Reason: loadErr.Error()})
					continue
				}
				newSkills, skErr := skills.LoadSelected(newCfg.AgentSkillsDir, newCfg.AgentDefaultSkills)
				if skErr != nil {
					logger.Warn("SIGHUP skill reload failed, keeping existing skills", "err", skErr)
					newSkills = nil
				}
				cfgPtr.Store(&newCfg)
				runner.UpdateFullOptions(newSkills, newCfg.AgentMaxSteps, newCfg.AgentMaxTokens, newCfg.LLMFastModel, newCfg.AgentAdversarialSecurity)
				pool.UpdateRuntimeConfig(newCfg.StickySummary, newCfg.AlertWebhookURL, newCfg.AllowSameOwnerCrossRepo, newCfg.CrossRepoAllowlist)
				auditLog.Log(audit.Event{Action: "config_reload", Decision: "allow", Reason: fmt.Sprintf("reloaded %d skills", len(newSkills))})
				eventBroker.Publish(events.Event{
					Type:    "config_reload",
					Message: fmt.Sprintf("Reloaded config & %d skills via SIGHUP", len(newSkills)),
				})
				logger.Info("reloaded configuration and skills via SIGHUP", "skills", len(newSkills))
			}
		}
	}()

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           buildHTTPHandler(cfg, pool, st, metricsCollector, eventBroker, memStore, auditLog, orgGraph),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		logger.Info("CodeSpider 24/7 daemon listening", "addr", cfg.ListenAddr, "model", cfg.LLMModel)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("http server error", "err", err)
			stop()
		}
	}()

	<-ctx.Done()
	logger.Info("shutting down CodeSpider daemon")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
	pool.Wait()
	logger.Info("CodeSpider stopped cleanly")
}

func buildHTTPHandler(cfg config.Config, pool *worker.Pool, st *store.Store, mc *metrics.Collector, broker *events.Broker, mem *memory.Store, auditLog *audit.Logger, orgGraph *orggraph.Graph) http.Handler {
	mux := http.NewServeMux()
	registerOperationsAPI(mux, cfg.AdminToken, apiDeps{
		pool:      pool,
		store:     st,
		audit:     auditLog,
		orgGraph:  orgGraph,
		langReg:   lang.NewDefaultRegistry(),
		skillsDir: cfg.AgentSkillsDir,
	})
	mux.Handle("/webhook", &gitea.WebhookHandler{
		Secret:        cfg.GiteaWebhookSecret,
		RequireSecret: !cfg.AllowUnsignedWebhooks,
		BotUsername:   cfg.GiteaBotUsername,
		SkipDrafts:    cfg.SkipDraftPRs,
		IgnoreBots:    cfg.IgnoreBotPRs,
		OnTrigger:     pool.Enqueue,
		OnEvent:       mc.RecordWebhook,
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ready"))
	})
	mux.HandleFunc("/api/session", func(w http.ResponseWriter, r *http.Request) {
		handleSessionLogin(w, r, cfg.AdminToken)
	})
	mux.HandleFunc("/status", requireAdminToken(cfg.AdminToken, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		active := pool.ActiveCount()
		depth := pool.QueueDepth()
		reviewed := 0
		if st != nil {
			reviewed = st.ReviewedPRCount()
		}
		var recent []store.RunRecord
		if st != nil {
			recent = st.RecentRuns()
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"model":        cfg.LLMModel,
			"workers":      cfg.Workers,
			"active_jobs":  active,
			"queue_depth":  depth,
			"reviewed_prs": reviewed,
			"metrics":      mc.Snapshot(active, depth, reviewed),
			"recent_runs":  recent,
		})
	}))
	mux.HandleFunc("/metrics", requireAdminToken(cfg.AdminToken, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		reviewed := 0
		if st != nil {
			reviewed = st.ReviewedPRCount()
		}
		mc.WritePrometheus(w, pool.ActiveCount(), pool.QueueDepth(), reviewed)
	}))
	mux.HandleFunc("/events", requireAdminToken(cfg.AdminToken, func(w http.ResponseWriter, r *http.Request) {
		serveSSE(w, r, broker)
	}))
	mux.HandleFunc("/api/dry-run", requireAdminToken(cfg.AdminToken, func(w http.ResponseWriter, r *http.Request) {
		handleDryRun(w, r, pool)
	}))
	mux.HandleFunc("/api/memory", requireAdminToken(cfg.AdminToken, func(w http.ResponseWriter, r *http.Request) {
		handleMemoryAPI(w, r, mem)
	}))
	mux.HandleFunc("/api/memory/simulate", requireAdminToken(cfg.AdminToken, func(w http.ResponseWriter, r *http.Request) {
		handleMemorySimulate(w, r)
	}))
	mux.HandleFunc("/dashboard", withSecurityHeaders(serveDashboard))
	mux.HandleFunc("/", withSecurityHeaders(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		serveDashboard(w, r)
	}))
	return mux
}

func withSecurityHeaders(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'")
		next(w, r)
	}
}

func handleSessionLogin(w http.ResponseWriter, r *http.Request, adminToken string) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method == http.MethodGet {
		if adminToken == "" {
			_ = json.NewEncoder(w).Encode(map[string]any{"authenticated": true, "auth_required": false})
			return
		}
		if c, err := r.Cookie(sessionCookieName); err == nil {
			if csrf, ok := verifySessionCookie(c.Value, adminToken, time.Now()); ok {
				_ = json.NewEncoder(w).Encode(map[string]any{"authenticated": true, "auth_required": true, "csrf_token": csrf})
				return
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"authenticated": false, "auth_required": true})
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if adminToken == "" {
		_ = json.NewEncoder(w).Encode(map[string]any{"authenticated": true, "auth_required": false})
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 4096))
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	var req struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if !constantTimeEqual(req.Token, adminToken) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	exp := time.Now().Add(12 * time.Hour).Unix()
	cookieVal, csrfToken, err := issueSessionToken(adminToken, exp)
	if err != nil {
		http.Error(w, "session error", http.StatusInternalServerError)
		return
	}
	isTLS := r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    cookieVal,
		Path:     "/",
		HttpOnly: true,
		Secure:   isTLS,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   12 * 3600,
	})
	_ = json.NewEncoder(w).Encode(map[string]any{
		"authenticated": true,
		"auth_required": true,
		"csrf_token":    csrfToken,
		"expires_at":    exp,
	})
}

func issueSessionToken(adminToken string, expUnix int64) (cookieVal, csrfToken string, err error) {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", "", err
	}
	payload := fmt.Sprintf("%d.%s", expUnix, hex.EncodeToString(nonce[:]))
	sig := hmacHex(adminToken, "session:"+payload)
	csrf := hmacHex(adminToken, "csrf:"+payload)
	return payload + "." + sig, csrf, nil
}

func verifySessionCookie(raw, adminToken string, now time.Time) (csrfToken string, ok bool) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return "", false
	}
	exp, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || now.Unix() > exp {
		return "", false
	}
	payload := parts[0] + "." + parts[1]
	expected := hmacHex(adminToken, "session:"+payload)
	if !constantTimeEqual(parts[2], expected) {
		return "", false
	}
	return hmacHex(adminToken, "csrf:"+payload), true
}

func hmacHex(secret, msg string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(msg))
	return hex.EncodeToString(mac.Sum(nil))
}

func constantTimeEqual(a, b string) bool {
	return len(a) == len(b) && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func isUnsafeMethod(method string) bool {
	return method != http.MethodGet && method != http.MethodHead && method != http.MethodOptions
}

func checkCSRF(r *http.Request, expectedCSRF string) bool {
	if sfs := strings.ToLower(strings.TrimSpace(r.Header.Get("Sec-Fetch-Site"))); sfs == "cross-site" {
		return false
	}
	if origin := strings.TrimSpace(r.Header.Get("Origin")); origin != "" && r.Host != "" {
		if u, err := url.Parse(origin); err == nil && !strings.EqualFold(u.Host, r.Host) {
			return false
		}
	}
	got := strings.TrimSpace(r.Header.Get("X-CSRF-Token"))
	return got != "" && constantTimeEqual(got, expectedCSRF)
}

func requireAdminToken(adminToken string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if adminToken == "" {
			next(w, r)
			return
		}
		if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
			if constantTimeEqual(strings.TrimSpace(strings.TrimPrefix(auth, "Bearer ")), adminToken) {
				next(w, r)
				return
			}
		}
		if _, pass, ok := r.BasicAuth(); ok && constantTimeEqual(pass, adminToken) {
			next(w, r)
			return
		}
		if c, err := r.Cookie(sessionCookieName); err == nil {
			if csrf, ok := verifySessionCookie(c.Value, adminToken, time.Now()); ok {
				if isUnsafeMethod(r.Method) && !checkCSRF(r, csrf) {
					http.Error(w, "csrf validation failed", http.StatusForbidden)
					return
				}
				next(w, r)
				return
			}
		}
		w.Header().Set("WWW-Authenticate", `Bearer realm="CodeSpider"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}
}

func serveSSE(w http.ResponseWriter, r *http.Request, broker *events.Broker) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	if broker == nil {
		flusher.Flush()
		return
	}

	once := r.URL.Query().Get("once") == "1"
	var history []events.Event
	var ch <-chan events.Event
	if once {
		history = broker.Recent()
	} else {
		history, ch = broker.Subscribe(r.Context())
	}
	for _, ev := range history {
		if b, err := json.Marshal(ev); err == nil {
			_, _ = fmt.Fprintf(w, "data: %s\n\n", b)
		}
	}
	flusher.Flush()

	if once {
		return
	}

	for {
		select {
		case <-r.Context().Done():
			return
		case ev, open := <-ch:
			if !open {
				return
			}
			if b, err := json.Marshal(ev); err == nil {
				_, _ = fmt.Fprintf(w, "data: %s\n\n", b)
				flusher.Flush()
			}
		}
	}
}

func handleDryRun(w http.ResponseWriter, r *http.Request, pool *worker.Pool) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, "failed to read request", http.StatusBadRequest)
		return
	}
	var req struct {
		Repo     string   `json:"repo"`
		PRNumber int64    `json:"pr_number"`
		Skills   []string `json:"skills"`
		Offline  bool     `json:"offline"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	owner, repo, ok := strings.Cut(strings.TrimSpace(req.Repo), "/")
	if !ok || owner == "" || repo == "" || req.PRNumber <= 0 {
		http.Error(w, "repo (owner/repo) and pr_number > 0 are required", http.StatusBadRequest)
		return
	}

	res, err := pool.ExecuteSync(r.Context(), gitea.ReviewTrigger{
		Kind:       "pr_review",
		Command:    "force_review",
		DryRun:     true,
		Offline:    req.Offline,
		Owner:      owner,
		Repo:       repo,
		PRNumber:   req.PRNumber,
		RepoSkills: req.Skills,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(res)
}

func handleMemoryAPI(w http.ResponseWriter, r *http.Request, mem *memory.Store) {
	if mem == nil {
		http.Error(w, "memory store unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	switch r.Method {
	case http.MethodGet:
		_ = json.NewEncoder(w).Encode(mem.Export())
	case http.MethodPost:
		body, err := io.ReadAll(io.LimitReader(r.Body, 256*1024))
		if err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		var req struct {
			Kind     string                 `json:"kind"` // feedback, rule, incident
			Feedback *memory.FeedbackRecord `json:"feedback,omitempty"`
			Rule     *memory.PolicyRule     `json:"rule,omitempty"`
			Incident *memory.IncidentRecord `json:"incident,omitempty"`
		}
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		switch req.Kind {
		case "feedback":
			if req.Feedback == nil {
				http.Error(w, "feedback payload required", http.StatusBadRequest)
				return
			}
			if err := mem.RecordFeedback(true, *req.Feedback); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
		case "rule":
			if req.Rule == nil {
				http.Error(w, "rule payload required", http.StatusBadRequest)
				return
			}
			if err := mem.UpsertRule(true, *req.Rule); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
		case "incident":
			if req.Incident == nil {
				http.Error(w, "incident payload required", http.StatusBadRequest)
				return
			}
			if err := mem.RecordIncident(true, *req.Incident); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
		default:
			http.Error(w, "kind must be feedback, rule, or incident", http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusCreated)
	case http.MethodDelete:
		key := strings.TrimSpace(r.URL.Query().Get("id"))
		if key == "" {
			http.Error(w, "id query parameter is required", http.StatusBadRequest)
			return
		}
		removed, err := mem.Delete(true, key)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]bool{"removed": removed})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func handleMemorySimulate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 512*1024))
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	var req struct {
		Rule     memory.PolicyRule  `json:"rule"`
		Findings []evidence.Finding `json:"findings"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(memory.SimulatePolicy(req.Rule, req.Findings))
}

func newLogger(level string) *slog.Logger {
	var lvl slog.Level
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: lvl}))
}
