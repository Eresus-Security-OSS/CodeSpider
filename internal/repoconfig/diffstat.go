package repoconfig

import "strings"

// FileStat summarizes one file section of a unified diff.
type FileStat struct {
	Path    string
	Added   int
	Removed int
	Binary  bool
}

// DiffFileStats returns per-file added/removed line counts for a unified diff.
// Only lines inside hunks are counted, so header lines ("--- a/x", "+++ b/x") and
// removed lines that happen to start with "--" are handled correctly.
func DiffFileStats(diff string) []FileStat {
	if diff == "" {
		return nil
	}
	var stats []FileStat
	for _, chunk := range splitDiffChunks(diff) {
		path := extractDiffPath(chunk)
		if path == "" {
			continue
		}
		st := FileStat{Path: path}
		inHunk := false
		for _, line := range strings.Split(chunk, "\n") {
			switch {
			case strings.HasPrefix(line, "@@"):
				inHunk = true
			case strings.HasPrefix(line, "Binary files ") || strings.HasPrefix(line, "GIT binary patch"):
				st.Binary = true
			case inHunk && strings.HasPrefix(line, "+"):
				st.Added++
			case inHunk && strings.HasPrefix(line, "-"):
				st.Removed++
			}
		}
		stats = append(stats, st)
	}
	return stats
}
