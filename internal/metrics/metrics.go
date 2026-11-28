// Package metrics provides zero-dependency atomic counters and Prometheus/JSON snapshots.
package metrics

import (
	"fmt"
	"io"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// Summary is a JSON-serializable snapshot of daemon metrics.
type Summary struct {
	UptimeSeconds       int64 `json:"uptime_seconds"`
	ActiveJobs          int   `json:"active_jobs"`
	QueueDepth          int   `json:"queue_depth"`
	ReviewedPRs         int   `json:"reviewed_prs"`
	RunsSuccess         int64 `json:"runs_success"`
	RunsFailed          int64 `json:"runs_failed"`
	RunsCanceled        int64 `json:"runs_canceled"`
	RunsSkipped         int64 `json:"runs_skipped"`
	TotalSteps          int64 `json:"total_steps"`
	TotalTokens         int64 `json:"total_tokens"`
	TotalInlineComments int64 `json:"total_inline_comments"`
	ReconcileRuns       int64 `json:"reconcile_runs"`
	WebhooksAccepted    int64 `json:"webhooks_accepted"`
	WebhooksIgnored     int64 `json:"webhooks_ignored"`
	WebhooksRejected    int64 `json:"webhooks_rejected"`
}

// Collector tracks daemon runtime metrics safely across goroutines.
type Collector struct {
	startedAt time.Time

	runsSuccess  atomic.Int64
	runsFailed   atomic.Int64
	runsCanceled atomic.Int64
	runsSkipped  atomic.Int64

	stepsTotal          atomic.Int64
	tokensTotal         atomic.Int64
	inlineCommentsTotal atomic.Int64
	runDurationCount    atomic.Int64
	runDurationMsSum    atomic.Int64

	webhooksAccepted atomic.Int64
	webhooksIgnored  atomic.Int64
	webhooksRejected atomic.Int64
	webhooksError    atomic.Int64

	reconcileSuccess atomic.Int64
	reconcileError   atomic.Int64

	mu             sync.Mutex
	webhookByLabel map[string]int64
	runByLabel     map[string]int64
}

// NewCollector initializes a metrics Collector.
func NewCollector() *Collector {
	return &Collector{
		startedAt:      time.Now().UTC(),
		webhookByLabel: make(map[string]int64),
		runByLabel:     make(map[string]int64),
	}
}

// RecordWebhook records an incoming webhook event by event type and outcome.
func (c *Collector) RecordWebhook(eventType, outcome string) {
	if c == nil {
		return
	}
	eventType = normalizeWebhookEvent(eventType)
	outcome = normalizeWebhookOutcome(outcome)
	switch outcome {
	case "accepted":
		c.webhooksAccepted.Add(1)
	case "ignored":
		c.webhooksIgnored.Add(1)
	case "rejected":
		c.webhooksRejected.Add(1)
	case "error":
		c.webhooksError.Add(1)
	}
	key := eventType + "\x00" + outcome
	c.mu.Lock()
	c.webhookByLabel[key]++
	c.mu.Unlock()
}

func normalizeWebhookEvent(eventType string) string {
	switch eventType {
	case "":
		return "unknown"
	case "pull_request",
		"issue_comment",
		"pull_request_comment",
		"pull_request_review_comment",
		"pull_request_review",
		"push",
		"ping",
		"issues",
		"create",
		"delete",
		"release",
		"status":
		return eventType
	default:
		return "other"
	}
}

func normalizeWebhookOutcome(outcome string) string {
	switch outcome {
	case "accepted", "ignored", "rejected", "error":
		return outcome
	default:
		return "other"
	}
}

// RecordRun records the outcome and resource consumption of a review/reply run.
func (c *Collector) RecordRun(kind, status string, steps, tokens, comments int, duration time.Duration) {
	if c == nil {
		return
	}
	switch status {
	case "success":
		c.runsSuccess.Add(1)
	case "failed":
		c.runsFailed.Add(1)
	case "canceled":
		c.runsCanceled.Add(1)
	case "skipped":
		c.runsSkipped.Add(1)
	}
	if steps > 0 {
		c.stepsTotal.Add(int64(steps))
	}
	if tokens > 0 {
		c.tokensTotal.Add(int64(tokens))
	}
	if comments > 0 {
		c.inlineCommentsTotal.Add(int64(comments))
	}
	if status != "skipped" {
		c.runDurationCount.Add(1)
		c.runDurationMsSum.Add(duration.Milliseconds())
	}
	key := kind + "\x00" + status
	c.mu.Lock()
	c.runByLabel[key]++
	c.mu.Unlock()
}

// RecordReconcile records a periodic PR reconciliation pass.
func (c *Collector) RecordReconcile(ok bool) {
	if c == nil {
		return
	}
	if ok {
		c.reconcileSuccess.Add(1)
	} else {
		c.reconcileError.Add(1)
	}
}

// Snapshot returns a point-in-time Summary for JSON status endpoints and dashboards.
func (c *Collector) Snapshot(activeJobs, queueDepth, reviewedPRs int) Summary {
	return Summary{
		UptimeSeconds:       int64(time.Since(c.startedAt).Seconds()),
		ActiveJobs:          activeJobs,
		QueueDepth:          queueDepth,
		ReviewedPRs:         reviewedPRs,
		RunsSuccess:         c.runsSuccess.Load(),
		RunsFailed:          c.runsFailed.Load(),
		RunsCanceled:        c.runsCanceled.Load(),
		RunsSkipped:         c.runsSkipped.Load(),
		TotalSteps:          c.stepsTotal.Load(),
		TotalTokens:         c.tokensTotal.Load(),
		TotalInlineComments: c.inlineCommentsTotal.Load(),
		ReconcileRuns:       c.reconcileSuccess.Load() + c.reconcileError.Load(),
		WebhooksAccepted:    c.webhooksAccepted.Load(),
		WebhooksIgnored:     c.webhooksIgnored.Load(),
		WebhooksRejected:    c.webhooksRejected.Load(),
	}
}

// WritePrometheus writes metrics in Prometheus text exposition format.
func (c *Collector) WritePrometheus(w io.Writer, activeJobs, queueDepth, reviewedPRs int) {
	fmt.Fprintf(w, "# HELP codespider_uptime_seconds Seconds since daemon startup.\n")
	fmt.Fprintf(w, "# TYPE codespider_uptime_seconds gauge\n")
	fmt.Fprintf(w, "codespider_uptime_seconds %d\n", int64(time.Since(c.startedAt).Seconds()))

	fmt.Fprintf(w, "# HELP codespider_active_jobs Currently executing PR review jobs.\n")
	fmt.Fprintf(w, "# TYPE codespider_active_jobs gauge\n")
	fmt.Fprintf(w, "codespider_active_jobs %d\n", activeJobs)

	fmt.Fprintf(w, "# HELP codespider_queue_depth Queued triggers waiting for a worker.\n")
	fmt.Fprintf(w, "# TYPE codespider_queue_depth gauge\n")
	fmt.Fprintf(w, "codespider_queue_depth %d\n", queueDepth)

	fmt.Fprintf(w, "# HELP codespider_reviewed_prs Total PRs with a recorded reviewed commit SHA.\n")
	fmt.Fprintf(w, "# TYPE codespider_reviewed_prs gauge\n")
	fmt.Fprintf(w, "codespider_reviewed_prs %d\n", reviewedPRs)

	fmt.Fprintf(w, "# HELP codespider_agent_steps_total Total LLM tool-calling steps executed.\n")
	fmt.Fprintf(w, "# TYPE codespider_agent_steps_total counter\n")
	fmt.Fprintf(w, "codespider_agent_steps_total %d\n", c.stepsTotal.Load())

	fmt.Fprintf(w, "# HELP codespider_agent_tokens_total Total LLM tokens consumed.\n")
	fmt.Fprintf(w, "# TYPE codespider_agent_tokens_total counter\n")
	fmt.Fprintf(w, "codespider_agent_tokens_total %d\n", c.tokensTotal.Load())

	fmt.Fprintf(w, "# HELP codespider_inline_comments_total Total inline PR comments staged.\n")
	fmt.Fprintf(w, "# TYPE codespider_inline_comments_total counter\n")
	fmt.Fprintf(w, "codespider_inline_comments_total %d\n", c.inlineCommentsTotal.Load())

	fmt.Fprintf(w, "# HELP codespider_run_duration_ms_sum Sum of agent run durations in milliseconds.\n")
	fmt.Fprintf(w, "# TYPE codespider_run_duration_ms_sum counter\n")
	fmt.Fprintf(w, "codespider_run_duration_ms_sum %d\n", c.runDurationMsSum.Load())

	fmt.Fprintf(w, "# HELP codespider_run_duration_ms_count Number of timed agent runs.\n")
	fmt.Fprintf(w, "# TYPE codespider_run_duration_ms_count counter\n")
	fmt.Fprintf(w, "codespider_run_duration_ms_count %d\n", c.runDurationCount.Load())

	fmt.Fprintf(w, "# HELP codespider_reconcile_runs_total Total periodic reconciliation passes.\n")
	fmt.Fprintf(w, "# TYPE codespider_reconcile_runs_total counter\n")
	fmt.Fprintf(w, "codespider_reconcile_runs_total{status=\"success\"} %d\n", c.reconcileSuccess.Load())
	fmt.Fprintf(w, "codespider_reconcile_runs_total{status=\"error\"} %d\n", c.reconcileError.Load())

	c.mu.Lock()
	whKeys := make([]string, 0, len(c.webhookByLabel))
	for k := range c.webhookByLabel {
		whKeys = append(whKeys, k)
	}
	sort.Strings(whKeys)
	whCopy := make(map[string]int64, len(whKeys))
	for _, k := range whKeys {
		whCopy[k] = c.webhookByLabel[k]
	}

	runKeys := make([]string, 0, len(c.runByLabel))
	for k := range c.runByLabel {
		runKeys = append(runKeys, k)
	}
	sort.Strings(runKeys)
	runCopy := make(map[string]int64, len(runKeys))
	for _, k := range runKeys {
		runCopy[k] = c.runByLabel[k]
	}
	c.mu.Unlock()

	fmt.Fprintf(w, "# HELP codespider_webhooks_total Total webhook requests processed.\n")
	fmt.Fprintf(w, "# TYPE codespider_webhooks_total counter\n")
	for _, k := range whKeys {
		var ev, out string
		for i := 0; i < len(k); i++ {
			if k[i] == 0 {
				ev, out = k[:i], k[i+1:]
				break
			}
		}
		fmt.Fprintf(w, "codespider_webhooks_total{event=%q,outcome=%q} %d\n", ev, out, whCopy[k])
	}

	fmt.Fprintf(w, "# HELP codespider_runs_total Total agent runs by kind and status.\n")
	fmt.Fprintf(w, "# TYPE codespider_runs_total counter\n")
	for _, k := range runKeys {
		var kind, status string
		for i := 0; i < len(k); i++ {
			if k[i] == 0 {
				kind, status = k[:i], k[i+1:]
				break
			}
		}
		fmt.Fprintf(w, "codespider_runs_total{kind=%q,status=%q} %d\n", kind, status, runCopy[k])
	}
}
