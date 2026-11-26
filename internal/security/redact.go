package security

import (
	"regexp"
	"strings"
)

var (
	authHeaderRe  = regexp.MustCompile(`(?i)\b(Authorization:\s*(?:Bearer|Basic|Token)\s+)([^\s"'\r\n;]+)`)
	urlUserInfoRe = regexp.MustCompile(`(https?://)([^/\s:@]+):([^/\s@]+)@`)
	knownTokenRe  = regexp.MustCompile(`\b(ghp_[A-Za-z0-9]{12,}|github_pat_[A-Za-z0-9_]{20,}|glpat-[A-Za-z0-9_-]{12,}|sk-[A-Za-z0-9_-]{16,}|AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{10,})\b`)
)

// RedactText scrubs explicit secret literals, HTTP Authorization headers, URL userinfo credentials,
// and common API token formats from logs, SSE events, and error messages.
func RedactText(input string, extraLiterals ...string) string {
	if input == "" {
		return ""
	}
	out := strings.ReplaceAll(input, "\x00", "")
	for _, lit := range extraLiterals {
		if len(lit) >= 4 {
			out = strings.ReplaceAll(out, lit, "[REDACTED]")
		}
	}
	out = authHeaderRe.ReplaceAllString(out, "${1}[REDACTED]")
	out = urlUserInfoRe.ReplaceAllString(out, "${1}[REDACTED]:[REDACTED]@")
	out = knownTokenRe.ReplaceAllString(out, "[REDACTED]")
	return out
}
