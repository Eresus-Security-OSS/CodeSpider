package main

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/Eresus-Security-OSS/CodeSpider/internal/audit"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/benchmark"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/gitea"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/lang"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/orggraph"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/skills"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/store"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/worker"
)

type apiDeps struct {
	pool      *worker.Pool
	store     *store.Store
	audit     *audit.Logger
	orgGraph  *orggraph.Graph
	langReg   *lang.Registry
	skillsDir string
}

func registerOperationsAPI(mux *http.ServeMux, adminToken string, deps apiDeps) {
	mux.HandleFunc("/api/reviews", requireAdminToken(adminToken, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		if limit <= 0 {
			limit = 25
		}
		status := strings.TrimSpace(r.URL.Query().Get("status"))
		repo := strings.TrimSpace(r.URL.Query().Get("repo"))
		items, total := deps.store.ListRuns(offset, limit, status, repo)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"total":  total,
			"offset": offset,
			"limit":  limit,
			"items":  items,
		})
	}))

	mux.HandleFunc("/api/org-graph", requireAdminToken(adminToken, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(deps.orgGraph.View(nil))
	}))

	mux.HandleFunc("/api/languages", requireAdminToken(adminToken, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(deps.langReg.Statuses())
	}))

	mux.HandleFunc("/api/skills", requireAdminToken(adminToken, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		list, err := skills.DiscoverAll(deps.skillsDir)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"skills": list})
	}))

	mux.HandleFunc("/api/audit", requireAdminToken(adminToken, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		if limit <= 0 {
			limit = 100
		}
		events, err := deps.audit.ReadRecent(limit)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"events": events})
	}))

	mux.HandleFunc("/api/benchmarks", requireAdminToken(adminToken, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var summaries []benchmark.Summary
		for _, split := range []string{"dev", "validation", "holdout"} {
			p := "testdata/benchmarks/" + split + ".jsonl"
			cases, err := benchmark.LoadJSONL(p)
			if err != nil {
				continue
			}
			if sum, err := benchmark.RunOffline(p, cases); err == nil {
				summaries = append(summaries, sum)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"splits": summaries})
	}))

	mux.HandleFunc("/api/replay", requireAdminToken(adminToken, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 64*1024))
		if err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		var req struct {
			Repo     string   `json:"repo"`
			PRNumber int64    `json:"pr_number"`
			Skills   []string `json:"skills"`
			Offline  bool     `json:"offline"`
		}
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		owner, repo, ok := strings.Cut(strings.TrimSpace(req.Repo), "/")
		if !ok || owner == "" || repo == "" || req.PRNumber <= 0 {
			http.Error(w, "repo (owner/repo) and pr_number > 0 are required", http.StatusBadRequest)
			return
		}
		res, err := deps.pool.ExecuteSync(r.Context(), gitea.ReviewTrigger{
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
	}))
}
