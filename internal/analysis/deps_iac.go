package analysis

import (
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Eresus-Security-OSS/CodeSpider/internal/evidence"
)

// AnalyzeDepsAndIaC inspects go.mod, Dockerfile, docker-compose, and Kubernetes YAML diffs.
func AnalyzeDepsAndIaC(diff, commitSHA string) []evidence.Finding {
	if strings.TrimSpace(diff) == "" {
		return nil
	}
	var findings []evidence.Finding
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
			continue
		}
		if m := diffHunkLineRe.FindStringSubmatch(line); m != nil {
			if n, err := strconv.ParseInt(m[1], 10, 64); err == nil {
				newLine = n
				inHunk = true
			}
			continue
		}
		if !inHunk || currentFile == "" {
			continue
		}
		if strings.HasPrefix(line, " ") {
			newLine++
			continue
		}
		if strings.HasPrefix(line, "+") && !strings.HasPrefix(line, "+++") {
			added := strings.TrimSpace(line[1:])
			base := strings.ToLower(filepath.Base(currentFile))

			if base == "go.mod" {
				if strings.HasPrefix(added, "replace ") && (strings.Contains(added, "../") || strings.Contains(added, "./")) {
					findings = append(findings, makeStaticSecFinding("CS-DEP-001", "dependency", "critical", currentFile, newLine, "local_replace", commitSHA,
						"Local path replace directive in go.mod", "Local `replace` directive in `go.mod` breaks reproducible builds outside the author's machine.",
						"added go.mod replace: "+added))
				} else if strings.Contains(added, " v0.0.0-") {
					findings = append(findings, makeStaticSecFinding("CS-DEP-002", "dependency", "warning", currentFile, newLine, "pseudo_version", commitSHA,
						"Unpinned pseudo-version dependency in go.mod", "Added pseudo-version dependency (`v0.0.0-...`); prefer a tagged release for supply-chain traceability.",
						"added pseudo-version: "+added))
				} else if added != "" && !strings.HasPrefix(added, "//") && !strings.HasPrefix(added, "module ") &&
					!strings.HasPrefix(added, "go ") && !strings.HasPrefix(added, "require") && added != ")" && strings.Contains(added, " v") {
					findings = append(findings, makeStaticSecFinding("CS-DEP-003", "dependency", "info", currentFile, newLine, added, commitSHA,
						"New Go module dependency added", "New external dependency added (`"+added+"`); verify license compatibility and maintenance status.",
						"added module requirement: "+added))
				}
			}

			if isIaCFile(base) {
				lower := strings.ToLower(added)
				switch {
				case strings.Contains(lower, "privileged: true"):
					findings = append(findings, makeStaticSecFinding("CS-IAC-001", "iac-security", "critical", currentFile, newLine, "privileged_container", commitSHA,
						"Privileged container enabled", "`privileged: true` disables container isolation and grants host-level capabilities.",
						"matched privileged: true"))
				case strings.Contains(lower, "/var/run/docker.sock"):
					findings = append(findings, makeStaticSecFinding("CS-IAC-002", "iac-security", "critical", currentFile, newLine, "docker_sock_mount", commitSHA,
						"Docker socket mounted into container", "Mounting `/var/run/docker.sock` grants effective root access over the host daemon.",
						"matched /var/run/docker.sock mount"))
				case strings.Contains(lower, "network_mode: host") || strings.Contains(lower, "hostnetwork: true"):
					findings = append(findings, makeStaticSecFinding("CS-IAC-003", "iac-security", "warning", currentFile, newLine, "host_network", commitSHA,
						"Host network namespace enabled", "Host networking bypasses container network isolation.",
						"matched host networking directive"))
				case strings.Contains(lower, ":latest") && (strings.Contains(lower, "from ") || strings.Contains(lower, "image:")):
					findings = append(findings, makeStaticSecFinding("CS-IAC-004", "iac-security", "warning", currentFile, newLine, "latest_tag", commitSHA,
						"Unpinned :latest container image tag", "Using `:latest` hurts reproducibility and can pull breaking or compromised images.",
						"matched :latest image reference"))
				case strings.HasPrefix(lower, "user root") || strings.Contains(lower, "runasuser: 0"):
					findings = append(findings, makeStaticSecFinding("CS-IAC-005", "iac-security", "warning", currentFile, newLine, "root_user", commitSHA,
						"Container configured to run as root", "Prefer a non-root user (`nonroot` / UID > 0) for least privilege.",
						"matched root user directive"))
				}
			}
			newLine++
		}
	}
	return findings
}

func isIaCFile(base string) bool {
	return base == "dockerfile" || strings.HasPrefix(base, "dockerfile.") ||
		strings.Contains(base, "compose") || strings.HasSuffix(base, ".yaml") || strings.HasSuffix(base, ".yml")
}
