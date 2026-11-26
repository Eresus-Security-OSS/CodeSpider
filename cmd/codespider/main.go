// Command codespider runs the 24/7 agentic Gitea PR review daemon.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Eresus-Security-OSS/CodeSpider/internal/agent"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/config"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/gitea"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/llm"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/skills"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/store"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/worker"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/workspace"
)

func main() {
	cfg, err := config.LoadFromEnv()
	if err != nil {
		slog.Error("configuration error", "err", err)
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

	giteaClient := gitea.NewClient(cfg.GiteaBaseURL, cfg.GiteaToken)
	wsManager := workspace.NewManager(cfg.DataDir, cfg.GiteaToken)
	llmClient := llm.NewClient(cfg.LLMBaseURL, cfg.LLMAPIKey, cfg.LLMModel, cfg.LLMTimeout)
	runner := agent.NewRunner(llmClient, agent.Options{
		MaxSteps:    cfg.AgentMaxSteps,
		MaxTokens:   cfg.AgentMaxTokens,
		EnableWrite: cfg.AgentEnableWrite,
		Skills:      loadedSkills,
		Logger:      logger,
	})

	pool := worker.NewPool(worker.Config{
		Workers:     cfg.Workers,
		QueueSize:   128,
		EnableWrite: cfg.AgentEnableWrite,
		AuthorName:  cfg.GiteaBotUsername,
		Gitea:       giteaClient,
		Workspace:   wsManager,
		Agent:       runner,
		Store:       st,
		Logger:      logger,
	})

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	pool.Start(ctx)

	mux := http.NewServeMux()
	mux.Handle("/webhook", &gitea.WebhookHandler{
		Secret:      cfg.GiteaWebhookSecret,
		BotUsername: cfg.GiteaBotUsername,
		OnTrigger:   pool.Enqueue,
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ready"))
	})
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"active_jobs": pool.ActiveCount(),
			"recent_runs": st.RecentRuns(),
		})
	})

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           mux,
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
