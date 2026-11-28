package worker

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Eresus-Security-OSS/CodeSpider/internal/gitea"
)

// ErrStaleHeadSHA is returned when a PR's remote head commit changed mid-review.
var ErrStaleHeadSHA = errors.New("stale head SHA")

// StageMetric records the execution status and timing of one orchestration stage.
type StageMetric struct {
	Name       string `json:"name"`
	Status     string `json:"status"` // completed, skipped, failed
	DurationMs int64  `json:"duration_ms"`
	Detail     string `json:"detail,omitempty"`
}

func stageNames(stages []StageMetric) []string {
	out := make([]string, 0, len(stages))
	for _, s := range stages {
		out = append(out, s.Name+":"+s.Status)
	}
	return out
}

func (p *Pool) verifyHeadUnchanged(ctx context.Context, t gitea.ReviewTrigger) error {
	if t.DryRun || t.HeadSHA == "" || p.forge == nil || t.Kind != "pr_review" {
		return nil
	}
	curPR, err := p.forge.GetPullRequest(ctx, t.Owner, t.Repo, t.PRNumber)
	if err != nil {
		return nil // transient lookup error does not block if SHA was not observed to move
	}
	if curPR.Head.SHA != "" && !strings.EqualFold(curPR.Head.SHA, t.HeadSHA) {
		return fmt.Errorf("%w: expected %s, remote is %s", ErrStaleHeadSHA, t.HeadSHA, curPR.Head.SHA)
	}
	return nil
}

func recordStage(stages *[]StageMetric, name, status string, started time.Time, detail string) {
	*stages = append(*stages, StageMetric{
		Name:       name,
		Status:     status,
		DurationMs: time.Since(started).Milliseconds(),
		Detail:     detail,
	})
}
