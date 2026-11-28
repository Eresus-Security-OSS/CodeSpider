package repoconfig

import (
	"fmt"
	"path"
	"regexp"
	"strconv"
	"strings"
)

const maxTitlePatternLen = 256

// parseInlineList splits an inline YAML list such as `[main, "release/*"]`.
func parseInlineList(val string) []string {
	var out []string
	for _, part := range strings.Split(strings.Trim(strings.TrimSpace(val), "[]"), ",") {
		if item := strings.Trim(strings.TrimSpace(part), `"'`); item != "" {
			out = append(out, item)
		}
	}
	return out
}

// SkipReason explains why an automatic review should be skipped for a PR, or returns "".
// base_branches limits reviews to matching target branches (path.Match globs, so "release/*"
// matches "release/1.2" but not "release/1.2/hotfix"); ignore_title_keywords skips PRs whose
// title contains any keyword, case-insensitively.
func (c Config) SkipReason(baseRef, title string) string {
	if len(c.BaseBranches) > 0 && baseRef != "" {
		matched := false
		for _, pat := range c.BaseBranches {
			if ok, err := path.Match(pat, baseRef); err == nil && ok {
				matched = true
				break
			}
		}
		if !matched {
			return fmt.Sprintf("base branch %q is not listed in base_branches", baseRef)
		}
	}
	lower := strings.ToLower(title)
	for _, kw := range c.IgnoreTitleKeywords {
		if kw != "" && strings.Contains(lower, strings.ToLower(kw)) {
			return fmt.Sprintf("PR title contains ignore keyword %q", kw)
		}
	}
	return ""
}

// CheckResult is the outcome of one deterministic pre-merge check.
type CheckResult struct {
	Name   string
	Passed bool
	Detail string
}

// EvaluatePreMergeChecks runs the checks configured via title_pattern, require_description,
// and max_changed_lines. Unconfigured checks are omitted. Results are advisory: they are
// reported in the summary comment and never change commit status.
func (c Config) EvaluatePreMergeChecks(title, body string, changedLines int) []CheckResult {
	var out []CheckResult
	if c.TitlePattern != "" {
		res := CheckResult{Name: "PR title format"}
		re, err := regexp.Compile(c.TitlePattern)
		switch {
		case err != nil:
			res.Detail = "title_pattern is not a valid regular expression"
		case re.MatchString(strings.TrimSpace(title)):
			res.Passed = true
			res.Detail = "matches title_pattern"
		default:
			res.Detail = "does not match the configured title_pattern"
		}
		out = append(out, res)
	}
	if c.RequireDescription {
		res := CheckResult{Name: "PR description"}
		if strings.TrimSpace(body) == "" {
			res.Detail = "description is empty"
		} else {
			res.Passed = true
			res.Detail = "present"
		}
		out = append(out, res)
	}
	if c.MaxChangedLines > 0 {
		res := CheckResult{Name: "PR size"}
		if changedLines > c.MaxChangedLines {
			res.Detail = fmt.Sprintf("%d changed lines exceeds max_changed_lines %d", changedLines, c.MaxChangedLines)
		} else {
			res.Passed = true
			res.Detail = fmt.Sprintf("%d of %d changed lines", changedLines, c.MaxChangedLines)
		}
		out = append(out, res)
	}
	return out
}

// parseTitlePattern validates and bounds a title_pattern value.
func parseTitlePattern(val string) string {
	val = strings.Trim(strings.TrimSpace(val), `"'`)
	if len(val) > maxTitlePatternLen {
		return ""
	}
	return val
}

// parsePositiveInt parses a positive integer config value, returning 0 for anything else.
func parsePositiveInt(val string) int {
	n, err := strconv.Atoi(strings.Trim(strings.TrimSpace(val), `"'`))
	if err != nil || n < 0 {
		return 0
	}
	return n
}
