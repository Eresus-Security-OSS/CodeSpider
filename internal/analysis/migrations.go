package analysis

import (
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/Eresus-Security-OSS/CodeSpider/internal/evidence"
)

var (
	dropDDLRe      = regexp.MustCompile(`(?i)\b(DROP\s+TABLE|DROP\s+COLUMN|TRUNCATE\s+TABLE)\b`)
	notNullNoDefRe = regexp.MustCompile(`(?i)\bADD\s+COLUMN\b[^;]*\bNOT\s+NULL\b`)
	createIndexRe  = regexp.MustCompile(`(?i)\bCREATE\s+(?:UNIQUE\s+)?INDEX\b`)
	alterColTypeRe = regexp.MustCompile(`(?i)\bALTER\s+COLUMN\b[^;]*\bTYPE\b`)
)

// AnalyzeMigrations inspects SQL migration diffs for destructive DDL, table locks, and missing rollback scripts.
func AnalyzeMigrations(diff string, changedPaths []string, commitSHA string) []evidence.Finding {
	if strings.TrimSpace(diff) == "" {
		return nil
	}
	var findings []evidence.Finding
	pathSet := make(map[string]bool, len(changedPaths))
	for _, p := range changedPaths {
		pathSet[filepath.ToSlash(p)] = true
	}

	var currentFile string
	var newLine int64
	inHunk := false

	for _, line := range strings.Split(diff, "\n") {
		if strings.HasPrefix(line, "diff --git ") {
			inHunk = false
			currentFile = ""
			continue
		}
		if strings.HasPrefix(line, "+++ b/") {
			currentFile = filepath.ToSlash(strings.TrimSpace(strings.TrimPrefix(line, "+++ b/")))
			if strings.HasSuffix(strings.ToLower(currentFile), ".up.sql") {
				downFile := strings.TrimSuffix(currentFile, ".up.sql") + ".down.sql"
				if !pathSet[downFile] {
					f := evidence.Finding{
						RuleID:    "CS-MIG-004",
						Category:  "rollback-safety",
						Severity:  "warning",
						State:     evidence.StateStaticallySupported,
						Path:      currentFile,
						EndLine:   1,
						Symbol:    "missing_down_migration",
						CommitSHA: commitSHA,
						Title:     "Up migration without matching down migration",
						Body:      "Added `.up.sql` migration without a corresponding `" + downFile + "` rollback migration.",
						Evidence:  []string{"missing companion " + downFile + " in PR changed paths"},
					}
					f.Fingerprint = evidence.ComputeFingerprint(f.RuleID, f.Category, f.Path, f.Symbol)
					findings = append(findings, f)
				}
			}
			continue
		}
		if m := diffHunkLineRe.FindStringSubmatch(line); m != nil {
			if n, err := strconv.ParseInt(m[1], 10, 64); err == nil {
				newLine = n
				inHunk = true
			}
			continue
		}
		if !inHunk || !isSQLFile(currentFile) {
			continue
		}
		if strings.HasPrefix(line, " ") {
			newLine++
			continue
		}
		if strings.HasPrefix(line, "+") && !strings.HasPrefix(line, "+++") {
			added := line[1:]
			switch {
			case dropDDLRe.MatchString(added):
				findings = append(findings, makeStaticSecFinding("CS-MIG-001", "database-migration", "critical", currentFile, newLine, "destructive_ddl", commitSHA,
					"Destructive DDL in migration", "Destructive `DROP`/`TRUNCATE` statement breaks zero-downtime rollbacks and causes irreversible data loss if rolled back.",
					"matched destructive DDL: "+strings.TrimSpace(added)))
			case notNullNoDefRe.MatchString(added) && !strings.Contains(strings.ToUpper(added), "DEFAULT"):
				findings = append(findings, makeStaticSecFinding("CS-MIG-002", "database-migration", "warning", currentFile, newLine, "not_null_no_default", commitSHA,
					"NOT NULL column added without DEFAULT", "Adding a `NOT NULL` column without `DEFAULT` fails on non-empty tables or locks table writes during backfill.",
					"matched ADD COLUMN ... NOT NULL without DEFAULT"))
			case createIndexRe.MatchString(added) && !strings.Contains(strings.ToUpper(added), "CONCURRENTLY"):
				findings = append(findings, makeStaticSecFinding("CS-MIG-003", "database-migration", "warning", currentFile, newLine, "non_concurrent_index", commitSHA,
					"CREATE INDEX without CONCURRENTLY", "Creating an index without `CONCURRENTLY` acquires a table write lock in PostgreSQL.",
					"matched CREATE INDEX without CONCURRENTLY"))
			case alterColTypeRe.MatchString(added):
				findings = append(findings, makeStaticSecFinding("CS-MIG-005", "rollback-safety", "warning", currentFile, newLine, "alter_column_type", commitSHA,
					"ALTER COLUMN TYPE rewrites table", "`ALTER COLUMN ... TYPE` can rewrite the entire table under an exclusive lock and break older running replicas.",
					"matched ALTER COLUMN TYPE"))
			}
			newLine++
		}
	}
	return findings
}

func isSQLFile(path string) bool {
	lower := strings.ToLower(path)
	return strings.HasSuffix(lower, ".sql")
}
