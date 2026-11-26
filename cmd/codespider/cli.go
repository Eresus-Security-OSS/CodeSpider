package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Eresus-Security-OSS/CodeSpider/internal/agent"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/benchmark"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/config"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/gitea"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/llm"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/memory"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/metrics"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/sandbox"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/sarif"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/skills"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/store"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/worker"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/workspace"
)

func runReviewCLI(args []string) int {
	fs := flag.NewFlagSet("review", flag.ContinueOnError)
	cfgFlag := fs.String("f", "", "Path to codespider.yaml config file")
	repoFlag := fs.String("repo", "", "Repository slug (owner/repo)")
	prFlag := fs.Int64("pr", 0, "Pull request number")
	dryRun := fs.Bool("dry-run", false, "Run review without posting comments or mutating local state")
	offline := fs.Bool("offline", false, "Run deterministic analyzers only without calling an LLM")
	sarifPath := fs.String("sarif", "", "Optional output path to write SARIF 2.1.0 report")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	owner, repo, prNum, err := parseReviewTarget(*repoFlag, *prFlag, fs.Args())
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\nusage: codespider review [-f codespider.yaml] [--dry-run] [--offline] [--sarif out.sarif] <owner/repo#pr>\n", err)
		return 2
	}

	cfgPath := config.ResolvePath(*cfgFlag)
	cfg, err := config.LoadFromFile(cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "configuration error (%s): %v\n", cfgPath, err)
		return 1
	}

	logger := newLogger(cfg.LogLevel)
	loadedSkills, _ := skills.LoadSelected(cfg.AgentSkillsDir, cfg.AgentDefaultSkills)

	// In --dry-run mode, avoid creating/mutating data/state.json.
	var st *store.Store
	if !*dryRun {
		st, err = store.Open(cfg.DataDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "state store error: %v\n", err)
			return 1
		}
	}
	memStore, _ := memory.Open(cfg.DataDir)

	giteaClient := gitea.NewClient(cfg.GiteaBaseURL, cfg.GiteaToken)
	wsManager := workspace.NewManager(cfg.DataDir, cfg.GiteaToken).WithAllowedOrigin(cfg.GiteaBaseURL)
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
		Logger:              logger,
	})

	pool := worker.NewPool(worker.Config{
		Workers:                   1,
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
		Metrics:                   metrics.NewCollector(),
		Memory:                    memStore,
		Sandbox: sandbox.NewExecutor(sandbox.Config{
			Mode:    cfg.SandboxMode,
			Runtime: cfg.SandboxRuntime,
			Image:   cfg.SandboxImage,
		}),
		Logger: logger,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	res, err := pool.ExecuteSync(ctx, gitea.ReviewTrigger{
		Kind:     "pr_review",
		Command:  "force_review",
		DryRun:   *dryRun,
		Offline:  *offline,
		Owner:    owner,
		Repo:     repo,
		PRNumber: prNum,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "review failed: %v\n", err)
		return 1
	}

	if *sarifPath != "" {
		rawSarif, sErr := sarif.Marshal(res.Findings, res.SecretFindings)
		if sErr != nil {
			fmt.Fprintf(os.Stderr, "sarif marshal error: %v\n", sErr)
			return 1
		}
		if wErr := os.WriteFile(*sarifPath, rawSarif, 0o644); wErr != nil {
			fmt.Fprintf(os.Stderr, "write sarif error: %v\n", wErr)
			return 1
		}
	}

	fmt.Printf("PR: %s | Model: %s | Verdict: %s | Steps: %d | Tokens: %d | Refuted: %d | Suppressed: %d\n",
		res.PRKey, res.Model, res.Verdict, res.StepsUsed, res.TokensUsed, res.BlueTeamRefuted, res.SuppressedCount)
	if len(res.SecretFindings) > 0 {
		fmt.Printf("\nSecret Scan Alerts (%d):\n", len(res.SecretFindings))
		for _, f := range res.SecretFindings {
			fmt.Printf("  - [%s] %s at %s:%d (history_only=%v)\n", f.Kind, f.MaskedPreview, f.File, f.Line, f.InHistoryOnly)
		}
	}
	if len(res.InlineComments) > 0 {
		fmt.Printf("\nInline Comments (%d):\n", len(res.InlineComments))
		for _, c := range res.InlineComments {
			fmt.Printf("  - %s:%d: %s\n", c.Path, c.NewLineNum, c.Body)
		}
	}
	if res.Summary != "" {
		fmt.Printf("\nSummary:\n%s\n", res.Summary)
	}
	return 0
}

func runBenchCLI(args []string) int {
	fs := flag.NewFlagSet("bench", flag.ContinueOnError)
	dataset := fs.String("dataset", "testdata/benchmarks/local_suite.jsonl", "Path to JSONL benchmark dataset")
	split := fs.String("split", "", "Split to run: dev, validation, holdout, or all (overrides -dataset)")
	jsonOut := fs.Bool("json", false, "Output benchmark summary as JSON")
	offline := fs.Bool("offline", true, "Run deterministic offline benchmark")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if !*offline {
		fmt.Fprintln(os.Stderr, "live LLM benchmark mode requires --offline=false with configured API harness; use --offline for deterministic baseline")
		return 2
	}

	var paths []string
	switch strings.ToLower(strings.TrimSpace(*split)) {
	case "":
		paths = []string{*dataset}
	case "dev", "validation", "holdout":
		paths = []string{"testdata/benchmarks/" + strings.ToLower(*split) + ".jsonl"}
	case "all":
		paths = []string{
			"testdata/benchmarks/dev.jsonl",
			"testdata/benchmarks/validation.jsonl",
			"testdata/benchmarks/holdout.jsonl",
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown split %q (use dev, validation, holdout, or all)\n", *split)
		return 2
	}

	var summaries []benchmark.Summary
	for _, p := range paths {
		cases, err := benchmark.LoadJSONL(p)
		if err != nil {
			fmt.Fprintf(os.Stderr, "load dataset %s: %v\n", p, err)
			return 1
		}
		if err := benchmark.ValidateDataset(cases); err != nil {
			fmt.Fprintf(os.Stderr, "invalid dataset %s: %v\n", p, err)
			return 1
		}
		sum, err := benchmark.RunOffline(p, cases)
		if err != nil {
			fmt.Fprintf(os.Stderr, "benchmark failed: %v\n", err)
			return 1
		}
		summaries = append(summaries, sum)
	}

	if *jsonOut {
		_ = json.NewEncoder(os.Stdout).Encode(summaries)
		return 0
	}
	for _, sum := range summaries {
		fmt.Printf("Benchmark: %s (%s)\n", sum.Dataset, sum.Mode)
		fmt.Printf("Cases: %d | TP: %d | FP: %d | FN: %d | FP/PR: %.3f\n",
			sum.Cases, sum.TruePositives, sum.FalsePositives, sum.FalseNegatives, sum.FalsePositivesPerPR)
		fmt.Printf("Precision: %.3f [%.3f..%.3f] | Recall: %.3f [%.3f..%.3f] | F1: %.3f\n",
			sum.Precision, sum.PrecisionCI.Lower, sum.PrecisionCI.Upper,
			sum.Recall, sum.RecallCI.Lower, sum.RecallCI.Upper, sum.F1)
		fmt.Printf("FPR: %.3f [%.3f..%.3f] | LineAcc: %.3f | SevAcc: %.3f | AvgLatencyMs: %.2f\n\n",
			sum.FalsePositiveRate, sum.FPRateCI.Lower, sum.FPRateCI.Upper,
			sum.LineAccuracy, sum.SeverityAccuracy, sum.AvgLatencyMs)
	}
	return 0
}

func runHealthcheckCLI(args []string) int {
	fs := flag.NewFlagSet("healthcheck", flag.ContinueOnError)
	addr := fs.String("addr", "http://127.0.0.1:8080/healthz", "Healthcheck URL")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(*addr)
	if err != nil {
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return 1
	}
	return 0
}

func parseReviewTarget(repoFlag string, prFlag int64, positional []string) (owner, repo string, prNum int64, err error) {
	if repoFlag != "" && prFlag > 0 {
		o, r, ok := strings.Cut(strings.TrimSpace(repoFlag), "/")
		if ok && o != "" && r != "" {
			return o, r, prFlag, nil
		}
	}
	if len(positional) > 0 {
		slug, numStr, ok := strings.Cut(strings.TrimSpace(positional[0]), "#")
		if ok {
			o, r, okSlug := strings.Cut(slug, "/")
			n, parseErr := strconv.ParseInt(numStr, 10, 64)
			if okSlug && o != "" && r != "" && parseErr == nil && n > 0 {
				return o, r, n, nil
			}
		}
	}
	return "", "", 0, fmt.Errorf("expected <owner/repo#pr> or --repo <owner/repo> --pr <number>")
}
