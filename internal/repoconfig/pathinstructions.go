package repoconfig

import (
	"fmt"
	"strings"
)

const (
	maxPathInstructions     = 32
	maxPathInstructionBytes = 1024
)

// PathInstruction attaches a review instruction to files matching Pattern.
type PathInstruction struct {
	Pattern string
	Text    string
}

// parsePathInstruction splits a "<glob>: <instruction>" list item.
func parsePathInstruction(item string) (PathInstruction, bool) {
	pattern, text, ok := strings.Cut(item, ": ")
	if !ok {
		return PathInstruction{}, false
	}
	pattern = strings.TrimSpace(strings.Trim(pattern, `"'`))
	text = strings.TrimSpace(text)
	if pattern == "" || text == "" {
		return PathInstruction{}, false
	}
	if len(text) > maxPathInstructionBytes {
		text = text[:maxPathInstructionBytes]
	}
	return PathInstruction{Pattern: pattern, Text: text}, true
}

// InstructionsForPaths renders the path instructions whose glob matches at least one
// changed path. It returns "" when nothing matches.
func (c Config) InstructionsForPaths(changedPaths []string) string {
	if len(c.PathInstructions) == 0 || len(changedPaths) == 0 {
		return ""
	}
	var b strings.Builder
	n := 0
	for _, pi := range c.PathInstructions {
		if n >= maxPathInstructions {
			break
		}
		var matched []string
		for _, p := range changedPaths {
			if matchesAny(p, []string{pi.Pattern}) {
				matched = append(matched, p)
			}
		}
		if len(matched) == 0 {
			continue
		}
		if n == 0 {
			b.WriteString("### Path-specific review instructions\n")
		}
		n++
		shown := matched
		more := ""
		if len(shown) > 3 {
			more = fmt.Sprintf(" and %d more", len(shown)-3)
			shown = shown[:3]
		}
		fmt.Fprintf(&b, "- For files matching `%s` (%s%s): %s\n", pi.Pattern, strings.Join(shown, ", "), more, pi.Text)
	}
	return strings.TrimSpace(b.String())
}
