package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Eresus-Security-OSS/CodeSpider/internal/agent"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/gitea"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/policy"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/repoconfig"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/security"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/store"
)

const stickySummaryMarker = "<!-- codespider:sticky-summary -->"

func (p *Pool) runPostReviewAutomations(
	ctx context.Context,
	t gitea.ReviewTrigger,
	perms policy.PermissionSet,
	repoCfg repoconfig.Config,
	diff, wtDir, prAuthor string,
	res agent.RunResult,
	secretFindings []security.Finding,
) {
	if p.gitea == nil {
		return
	}

	p.mu.Lock()
	stickySummary := p.stickySummary
	alertWebhookURL := p.alertWebhookURL
	p.mu.Unlock()

	if stickySummary && t.Kind == "pr_review" && policy.CheckSideEffectAllowed(policy.EffectPostComment, perms) == nil {
		checks := repoCfg.EvaluatePreMergeChecks(t.PRTitle, t.PRBody, countDiffLines(diff))
		body := buildStickyWalkthrough(t, diff, res, secretFindings, checks)
		if err := p.gitea.UpsertStickyComment(ctx, t.Owner, t.Repo, t.PRNumber, stickySummaryMarker, body); err != nil {
			p.logger.Warn("failed to upsert sticky summary comment", "pr", t.PRNumber, "err", err)
		}
	}

	if repoCfg.AutoLabel && t.Kind == "pr_review" && policy.CheckSideEffectAllowed(policy.EffectMutateLabelsOrReviewer, perms) == nil {
		labels := computePRLabels(diff, res.HasCritical, secretFindings)
		if err := p.gitea.EnsureAndAddLabels(ctx, t.Owner, t.Repo, t.PRNumber, labels); err != nil {
			p.logger.Warn("failed to apply auto labels", "pr", t.PRNumber, "err", err)
		}
	}

	if repoCfg.AutoAssignReviewers && t.Kind == "pr_review" && policy.CheckSideEffectAllowed(policy.EffectMutateLabelsOrReviewer, perms) == nil {
		// Fork PRs must not choose their own reviewers, so their CODEOWNERS comes from the base branch.
		var rules []repoconfig.OwnerRule
		if t.IsFork {
			rules = repoconfig.LoadCodeOwnersFrom(p.baseFileReader(ctx, t))
		} else {
			rules = repoconfig.LoadCodeOwners(wtDir)
		}
		changed := repoconfig.ExtractChangedPaths(diff)
		reviewers := repoconfig.MatchCodeOwners(rules, changed, prAuthor, p.authorName)
		if len(reviewers) > 0 {
			if err := p.gitea.RequestReviewers(ctx, t.Owner, t.Repo, t.PRNumber, reviewers); err != nil {
				p.logger.Warn("failed to assign CODEOWNERS reviewers", "pr", t.PRNumber, "err", err)
			}
		}
	}

	if alertWebhookURL != "" && (res.HasCritical || len(secretFindings) > 0) && policy.CheckSideEffectAllowed(policy.EffectSendAlert, perms) == nil {
		prKey := store.PRKey(t.Owner, t.Repo, t.PRNumber)
		msg := fmt.Sprintf("[CodeSpider Alert] %s (commit %s): critical=%v, secret_findings=%d, inline_comments=%d",
			prKey, shortSHA(t.HeadSHA), res.HasCritical, len(secretFindings), res.InlineComments)
		if err := sendAlertWebhook(ctx, alertWebhookURL, msg, prKey, t.HeadSHA); err != nil {
			p.logger.Warn("failed to send alert webhook", "pr", prKey, "err", err)
		}
	}
}

func buildStickyWalkthrough(t gitea.ReviewTrigger, diff string, res agent.RunResult, secrets []security.Finding, checks []repoconfig.CheckResult) string {
	paths := repoconfig.ExtractChangedPaths(diff)
	var b strings.Builder
	b.WriteString(stickySummaryMarker + "\n")
	b.WriteString("## CodeSpider Review Summary\n\n")
	fmt.Fprintf(&b, "- **Commit:** `%s` | **Model:** `%s` | **Verdict:** `%s`\n", shortSHA(t.HeadSHA), res.ModelUsed, nonEmpty(res.Verdict, "COMMENT"))
	fmt.Fprintf(&b, "- **Findings:** `%d` inline comments | **Blue-Team Refuted:** `%d` | **Secret Alerts:** `%d`\n", res.InlineComments, res.BlueTeamRefuted, len(secrets))
	writeChangeOverview(&b, diff)
	b.WriteString("\n")
	writeChecksSection(&b, checks)
	if len(paths) > 0 {
		b.WriteString("```mermaid\nflowchart LR\n  PR[\"PR Changes\"]\n")
		areas := topLevelAreas(paths)
		for i, area := range areas {
			fmt.Fprintf(&b, "  PR --> A%d[\"%s\"]\n", i, strings.ReplaceAll(area, `"`, ""))
		}
		b.WriteString("```\n\n")
	}

	if len(secrets) > 0 {
		b.WriteString(security.FormatMarkdownReport(secrets))
		b.WriteString("\n")
	}
	if strings.TrimSpace(res.Summary) != "" {
		b.WriteString(strings.TrimSpace(res.Summary))
		b.WriteString("\n")
	}
	return b.String()
}

func topLevelAreas(paths []string) []string {
	set := make(map[string]struct{})
	for _, p := range paths {
		slash := filepath.ToSlash(p)
		parts := strings.Split(slash, "/")
		area := parts[0]
		if len(parts) > 2 {
			area = parts[0] + "/" + parts[1]
		}
		set[area] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for a := range set {
		out = append(out, a)
	}
	sort.Strings(out)
	if len(out) > 8 {
		out = out[:8]
	}
	return out
}

func computePRLabels(diff string, hasCritical bool, secrets []security.Finding) []string {
	lines := countDiffLines(diff)
	var sizeLabel string
	switch {
	case lines <= 20:
		sizeLabel = "size/XS"
	case lines <= 100:
		sizeLabel = "size/S"
	case lines <= 400:
		sizeLabel = "size/M"
	case lines <= 1000:
		sizeLabel = "size/L"
	default:
		sizeLabel = "size/XL"
	}

	labels := []string{sizeLabel}
	if hasCritical || len(secrets) > 0 {
		labels = append(labels, "security")
	}
	for _, p := range repoconfig.ExtractChangedPaths(diff) {
		lower := strings.ToLower(p)
		if strings.HasSuffix(lower, "_test.go") || strings.Contains(lower, ".test.") || strings.Contains(lower, ".spec.") {
			labels = append(labels, "tests")
			break
		}
	}
	return labels
}

func countDiffLines(diff string) int {
	n := 0
	for _, line := range strings.Split(diff, "\n") {
		if (strings.HasPrefix(line, "+") && !strings.HasPrefix(line, "+++")) ||
			(strings.HasPrefix(line, "-") && !strings.HasPrefix(line, "---")) {
			n++
		}
	}
	return n
}

func shortSHA(sha string) string {
	if len(sha) > 8 {
		return sha[:8]
	}
	if sha == "" {
		return "unknown"
	}
	return sha
}

func nonEmpty(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}

func sendAlertWebhook(ctx context.Context, webhookURL, message, prKey, sha string) error {
	payload, err := json.Marshal(map[string]string{
		"text":    message,
		"content": message,
		"pr":      prKey,
		"sha":     sha,
	})
	if err != nil {
		return err
	}
	reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, webhookURL, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.ReadAll(io.LimitReader(resp.Body, 8192))
	if resp.StatusCode >= 300 {
		return fmt.Errorf("alert webhook returned %s", resp.Status)
	}
	return nil
}
