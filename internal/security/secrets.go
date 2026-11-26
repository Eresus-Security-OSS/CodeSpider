// Package security scans PR commit histories and diffs for leaked credentials,
// including secrets added in early commits and deleted before HEAD.
package security

import (
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
)

// Finding describes a masked credential detected in a commit patch or diff.
type Finding struct {
	CommitSHA     string `json:"commit_sha,omitempty"`
	File          string `json:"file"`
	Line          int    `json:"line,omitempty"`
	Kind          string `json:"kind"`
	MaskedPreview string `json:"masked_preview"`
	InHistoryOnly bool   `json:"in_history_only"`
}

type secretPattern struct {
	kind string
	re   *regexp.Regexp
}

var (
	highConfidencePatterns = []secretPattern{
		{kind: "Private Key", re: regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----`)},
		{kind: "AWS Access Key", re: regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)},
		{kind: "GitHub Token", re: regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{36,}\b`)},
		{kind: "GitHub PAT", re: regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{22,}\b`)},
		{kind: "GitLab Token", re: regexp.MustCompile(`\bglpat-[A-Za-z0-9_-]{20,}\b`)},
		{kind: "LLM API Key", re: regexp.MustCompile(`\bsk-(?:proj-|ant-)?[A-Za-z0-9_-]{24,}\b`)},
		{kind: "Slack Token", re: regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{10,}\b`)},
	}
	genericAssignRe = regexp.MustCompile(`(?i)(?:api[_-]?key|secret|token|password|passwd)\s*[:=]\s*["']([^"'\s]{16,})["']`)
	commitHeaderRe  = regexp.MustCompile(`^commit ([0-9a-fA-F]{7,40})\b`)
	hunkStartRe     = regexp.MustCompile(`^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@`)
)

// MaskSecret redacts a secret value while keeping minimal prefix/suffix context for identification.
func MaskSecret(raw string) string {
	if len(raw) <= 8 {
		return "***REDACTED***"
	}
	return raw[:4] + "..." + raw[len(raw)-2:]
}

// ScanPatches scans intermediate commit patches (or headDiff if commitLogPatch is empty)
// and flags secrets, marking secrets that were deleted before HEAD as InHistoryOnly.
func ScanPatches(commitLogPatch, headDiff string) []Finding {
	source := commitLogPatch
	if strings.TrimSpace(source) == "" {
		source = headDiff
	}
	if strings.TrimSpace(source) == "" {
		return nil
	}

	headAdded := collectAddedLines(headDiff)

	var findings []Finding
	seen := make(map[string]struct{})

	lines := strings.Split(source, "\n")
	currentSHA := ""
	currentFile := ""
	newLine := 0

	for _, line := range lines {
		if m := commitHeaderRe.FindStringSubmatch(line); m != nil {
			currentSHA = m[1]
			if len(currentSHA) > 12 {
				currentSHA = currentSHA[:12]
			}
			continue
		}
		if strings.HasPrefix(line, "+++ b/") {
			currentFile = strings.TrimSpace(strings.TrimPrefix(line, "+++ b/"))
			continue
		}
		if m := hunkStartRe.FindStringSubmatch(line); m != nil {
			if n, err := strconv.Atoi(m[1]); err == nil {
				newLine = n
			}
			continue
		}
		if strings.HasPrefix(line, "+") && !strings.HasPrefix(line, "+++") {
			content := line[1:]
			matches := detectLineSecrets(content)
			for _, hit := range matches {
				masked := MaskSecret(hit.value)
				dedupKey := currentFile + "\x00" + hit.kind + "\x00" + masked
				if _, ok := seen[dedupKey]; ok {
					continue
				}
				seen[dedupKey] = struct{}{}

				inHistoryOnly := commitLogPatch != "" && !headAdded[strings.TrimSpace(content)]
				findings = append(findings, Finding{
					CommitSHA:     currentSHA,
					File:          currentFile,
					Line:          newLine,
					Kind:          hit.kind,
					MaskedPreview: masked,
					InHistoryOnly: inHistoryOnly,
				})
			}
			newLine++
		} else if strings.HasPrefix(line, " ") {
			newLine++
		}
	}

	return findings
}

// FormatMarkdownReport renders a masked Markdown summary of detected secret findings.
func FormatMarkdownReport(findings []Finding) string {
	if len(findings) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("### Commit-History Secret Scan Alert\n\n")
	for _, f := range findings {
		loc := f.File
		if f.Line > 0 {
			loc = fmt.Sprintf("%s:%d", f.File, f.Line)
		}
		historyNote := ""
		if f.InHistoryOnly {
			historyNote = " *(deleted in a later commit, but still present in PR git history — squash/rebase recommended)*"
		}
		shaPart := ""
		if f.CommitSHA != "" {
			shaPart = fmt.Sprintf(" in `%s`", f.CommitSHA)
		}
		fmt.Fprintf(&b, "- **%s** (`%s`) at `%s`%s%s\n", f.Kind, f.MaskedPreview, loc, shaPart, historyNote)
	}
	return b.String()
}

type secretMatch struct {
	kind  string
	value string
}

func detectLineSecrets(line string) []secretMatch {
	var out []secretMatch
	for _, pat := range highConfidencePatterns {
		if m := pat.re.FindString(line); m != "" && !isPlaceholder(m) {
			out = append(out, secretMatch{kind: pat.kind, value: m})
		}
	}
	if len(out) == 0 {
		if m := genericAssignRe.FindStringSubmatch(line); len(m) == 2 {
			val := m[1]
			if !isPlaceholder(val) && shannonEntropy(val) >= 3.75 {
				out = append(out, secretMatch{kind: "High-Entropy Secret", value: val})
			}
		}
	}
	return out
}

func collectAddedLines(diff string) map[string]bool {
	set := make(map[string]bool)
	for _, line := range strings.Split(diff, "\n") {
		if strings.HasPrefix(line, "+") && !strings.HasPrefix(line, "+++") {
			set[strings.TrimSpace(line[1:])] = true
		}
	}
	return set
}

func isPlaceholder(val string) bool {
	lower := strings.ToLower(val)
	if strings.Contains(val, "${") || strings.Contains(val, "{{") {
		return true
	}
	for _, marker := range []string{"replace-with", "example", "dummy", "changeme", "your-", "placeholder", "sk-test", "gt-token"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	counts := make(map[rune]int)
	total := 0
	for _, r := range s {
		counts[r]++
		total++
	}
	var entropy float64
	for _, c := range counts {
		p := float64(c) / float64(total)
		entropy -= p * math.Log2(p)
	}
	return entropy
}
