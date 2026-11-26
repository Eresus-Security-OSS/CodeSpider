# Benchmark Methodology

CodeSpider includes a reproducible evaluation harness (`internal/benchmark`, CLI: `codespider bench`) compatible with ReviewBench and SWE-PRBench-style JSONL fixtures.

## Metrics Measured

- **Precision:** `TP / (TP + FP)` — fraction of emitted findings that match a ground-truth issue in the same file and category.
- **Recall:** `TP / (TP + FN)` — fraction of ground-truth issues detected.
- **F1:** Harmonic mean of Precision and Recall.
- **False-Positive Rate (FPR):** Fraction of clean (zero-issue) PR fixtures that receive at least one spurious finding.
- **Inline Line Accuracy:** Fraction of matched findings whose reported `end_line` is within `±3` lines of the ground-truth line.
- **Avg Latency & Peak Memory:** Wall-clock time per PR and `runtime.MemStats.TotalAlloc` delta across the benchmark run.

## Dataset Format (JSONL)

Each line in `testdata/benchmarks/local_suite.jsonl` (or an imported ReviewBench/SWE-PRBench JSONL split) specifies:
- `id`, `repo`, `language`
- `diff`, optional `commit_patches` (for intermediate-commit secret detection)
- `base_files` and `files` (for AST/type contract diffing)
- `expected`: `[{file, line, category, severity}]`

## Context Ablation & Model Comparison

Following SWE-PRBench (`arxiv.org/abs/2603.26130`), CodeSpider separates deterministic evidence generation from LLM reasoning:
1. **Offline Deterministic Baseline (`--offline`):** Measures pure static/AST/invariant/secret-scan accuracy with zero LLM cost.
2. **Agentic Modes:** Compares models (`gpt-5`, `gpt-5-mini`, local vLLM) under equivalent `max_steps` and `max_tokens_per_run` budgets.

Run locally:
```bash
go run ./cmd/codespider bench --offline --dataset testdata/benchmarks/local_suite.jsonl
```
