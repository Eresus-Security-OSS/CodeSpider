package metrics

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestCollectorSnapshotAndPrometheus(t *testing.T) {
	c := NewCollector()
	c.RecordWebhook("pull_request", "accepted")
	c.RecordWebhook("issue_comment", "ignored")
	c.RecordRun("pr_review", "success", 4, 1200, 3, 250*time.Millisecond)
	c.RecordReconcile(true)

	snap := c.Snapshot(1, 2, 5)
	if snap.ActiveJobs != 1 || snap.QueueDepth != 2 || snap.ReviewedPRs != 5 {
		t.Fatalf("unexpected gauges: %+v", snap)
	}
	if snap.RunsSuccess != 1 || snap.TotalSteps != 4 || snap.TotalTokens != 1200 || snap.TotalInlineComments != 3 || snap.WebhooksAccepted != 1 || snap.ReconcileRuns != 1 {
		t.Fatalf("unexpected counters: %+v", snap)
	}

	var buf bytes.Buffer
	c.WritePrometheus(&buf, 1, 2, 5)
	text := buf.String()
	for _, want := range []string{
		"codespider_active_jobs 1",
		"codespider_agent_tokens_total 1200",
		`codespider_webhooks_total{event="pull_request",outcome="accepted"} 1`,
		`codespider_runs_total{kind="pr_review",status="success"} 1`,
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("prometheus output missing %q:\n%s", want, text)
		}
	}
}
