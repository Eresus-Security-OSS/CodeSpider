package repoconfig

import (
	"path/filepath"
	"sort"
	"strings"

	"github.com/Eresus-Security-OSS/CodeSpider/internal/workspace"
)

// OwnerRule maps a CODEOWNERS path pattern to Git usernames.
type OwnerRule struct {
	Pattern string
	Owners  []string
}

var codeOwnerFiles = []string{
	"CODEOWNERS",
	".gitea/CODEOWNERS",
	".github/CODEOWNERS",
}

// LoadCodeOwners reads the first CODEOWNERS file found in worktreeDir.
func LoadCodeOwners(worktreeDir string) []OwnerRule {
	if worktreeDir == "" {
		return nil
	}
	return LoadCodeOwnersFrom(func(rel string) ([]byte, error) {
		return workspace.ReadSafeFile(worktreeDir, rel, maxRepoConfigBytes)
	})
}

// LoadCodeOwnersFrom parses the first CODEOWNERS file that read can return.
func LoadCodeOwnersFrom(read FileReader) []OwnerRule {
	if read == nil {
		return nil
	}
	for _, rel := range codeOwnerFiles {
		raw, err := read(rel)
		if err != nil {
			continue
		}
		return parseCodeOwners(string(raw))
	}
	return nil
}

// MatchCodeOwners evaluates rules against changedPaths (last matching rule wins)
// and returns sorted, deduplicated usernames excluding any entries in excludeUsers.
func MatchCodeOwners(rules []OwnerRule, changedPaths []string, excludeUsers ...string) []string {
	if len(rules) == 0 || len(changedPaths) == 0 {
		return nil
	}
	excluded := make(map[string]bool, len(excludeUsers))
	for _, u := range excludeUsers {
		if u != "" {
			excluded[strings.ToLower(strings.TrimSpace(u))] = true
		}
	}

	selected := make(map[string]struct{})
	for _, p := range changedPaths {
		var matchedOwners []string
		for _, r := range rules {
			if matchesCodeOwnerPattern(p, r.Pattern) {
				matchedOwners = r.Owners
			}
		}
		for _, owner := range matchedOwners {
			if !excluded[strings.ToLower(owner)] {
				selected[owner] = struct{}{}
			}
		}
	}

	out := make([]string, 0, len(selected))
	for u := range selected {
		out = append(out, u)
	}
	sort.Strings(out)
	return out
}

func parseCodeOwners(content string) []OwnerRule {
	var rules []OwnerRule
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if idx := strings.Index(trimmed, " #"); idx != -1 {
			trimmed = strings.TrimSpace(trimmed[:idx])
		}
		fields := strings.Fields(trimmed)
		if len(fields) < 2 {
			continue
		}
		pattern := fields[0]
		var owners []string
		for _, tok := range fields[1:] {
			if !strings.HasPrefix(tok, "@") {
				continue
			}
			user := strings.TrimPrefix(tok, "@")
			// Skip team slugs like @org/team; Gitea reviewer requests take usernames.
			if user == "" || strings.Contains(user, "/") {
				continue
			}
			owners = append(owners, user)
		}
		if len(owners) > 0 {
			rules = append(rules, OwnerRule{Pattern: pattern, Owners: owners})
		}
	}
	return rules
}

func matchesCodeOwnerPattern(path, pattern string) bool {
	p := strings.TrimPrefix(filepath.ToSlash(pattern), "/")
	if p == "*" {
		return true
	}
	if strings.HasSuffix(p, "/") {
		return strings.HasPrefix(filepath.ToSlash(path), p)
	}
	return matchesAny(path, []string{p})
}
