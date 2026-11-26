// Package policy implements fail-closed, capability-based authorization and untrusted-input framing.
package policy

import (
	"fmt"
	"strings"
)

// TrustLevel classifies the provenance of a pull request or command trigger.
type TrustLevel string

const (
	TrustUntrustedFork TrustLevel = "untrusted_fork"
	TrustExternal      TrustLevel = "external"
	TrustCollaborator  TrustLevel = "collaborator"
)

// Capability is a bitmask of explicit tool and side-effect permissions.
type Capability uint32

const (
	CapReadWorktree Capability = 1 << iota
	CapPostReview
	CapCrossRepoRead
	CapWriteWorktree
	CapPushCommits
	CapIsolatedExec
	CapMutateMemory
)

// PermissionSet holds the evaluated capabilities and trust metadata for a single run.
type PermissionSet struct {
	Trust            TrustLevel
	Caps             Capability
	AllowedCrossRepo []string
	AllowSameOwner   bool
	Owner            string
}

// Has reports whether all bits in c are granted.
func (p PermissionSet) Has(c Capability) bool {
	return p.Caps&c == c
}

// Input captures verified metadata used to compute a PermissionSet.
type Input struct {
	Owner                   string
	IsFork                  bool
	IsCollaborator          bool
	DryRun                  bool
	EnableWrite             bool
	TriggerCommand          string
	SandboxMode             string
	AllowSameOwnerCrossRepo bool
	AllowedCrossRepos       []string
}

// EvaluatePermissions computes fail-closed capabilities from verified PR/command metadata.
// LLM outputs never influence this evaluation.
func EvaluatePermissions(in Input) PermissionSet {
	ps := PermissionSet{
		Trust: TrustExternal,
		Caps:  CapReadWorktree,
		Owner: in.Owner,
	}
	if !in.DryRun {
		ps.Caps |= CapPostReview
	}

	if in.IsFork {
		ps.Trust = TrustUntrustedFork
		// Fork PRs never receive cross-repo read, write, push, execution, or memory mutation caps.
		return ps
	}

	if in.IsCollaborator {
		ps.Trust = TrustCollaborator
		ps.Caps |= CapMutateMemory
	}

	if in.AllowSameOwnerCrossRepo || len(in.AllowedCrossRepos) > 0 {
		ps.Caps |= CapCrossRepoRead
		ps.AllowSameOwner = in.AllowSameOwnerCrossRepo
		ps.AllowedCrossRepo = append([]string(nil), in.AllowedCrossRepos...)
	}

	if in.EnableWrite && !in.DryRun && in.TriggerCommand == "fix" && in.IsCollaborator {
		ps.Caps |= CapWriteWorktree | CapPushCommits
	}

	if strings.EqualFold(strings.TrimSpace(in.SandboxMode), "container") {
		ps.Caps |= CapIsolatedExec
	}

	return ps
}

// RequiredCapability returns the capability required to execute toolName.
// Unknown tools fail closed with an error.
func RequiredCapability(toolName string) (Capability, error) {
	switch toolName {
	case "get_pr_diff", "get_incremental_diff", "read_file", "search_code", "list_files",
		"list_pr_comments", "list_pr_reviews", "git_forensics", "inspect_go_symbols", "inspect_symbols", "get_ci_status":
		return CapReadWorktree, nil
	case "add_inline_comment", "submit_review", "reply_comment", "record_verdict":
		return CapReadWorktree, nil
	case "search_org_repos":
		return CapCrossRepoRead, nil
	case "write_file", "edit_file":
		return CapWriteWorktree, nil
	case "commit_and_push":
		return CapPushCommits, nil
	case "run_proof_test":
		return CapIsolatedExec, nil
	default:
		return 0, fmt.Errorf("unknown or unpermitted tool %q", toolName)
	}
}

// CheckToolAllowed enforces capability-based authorization before executing a tool.
func CheckToolAllowed(toolName string, perms PermissionSet) error {
	req, err := RequiredCapability(toolName)
	if err != nil {
		return err
	}
	if !perms.Has(req) {
		return fmt.Errorf("permission denied for tool %q (trust=%s)", toolName, perms.Trust)
	}
	return nil
}

// SideEffect identifies an external or persistent mutation performed by the daemon.
type SideEffect string

const (
	EffectPostReview             SideEffect = "post_review"
	EffectPostComment            SideEffect = "post_comment"
	EffectSetCommitStatus        SideEffect = "set_commit_status"
	EffectMutateLabelsOrReviewer SideEffect = "mutate_labels_or_reviewers"
	EffectSendAlert              SideEffect = "send_alert"
	EffectGitPush                SideEffect = "git_push"
	EffectIsolatedExec           SideEffect = "isolated_exec"
	EffectMutateMemory           SideEffect = "mutate_memory"
)

// CheckSideEffectAllowed enforces fail-closed capability checks before any external mutation.
func CheckSideEffectAllowed(effect SideEffect, perms PermissionSet) error {
	var req Capability
	switch effect {
	case EffectPostReview, EffectPostComment, EffectSetCommitStatus, EffectMutateLabelsOrReviewer, EffectSendAlert:
		req = CapPostReview
	case EffectGitPush:
		req = CapPushCommits
	case EffectIsolatedExec:
		req = CapIsolatedExec
	case EffectMutateMemory:
		req = CapMutateMemory
	default:
		return fmt.Errorf("unknown side effect %q", effect)
	}
	if !perms.Has(req) {
		return fmt.Errorf("side effect %q denied (trust=%s)", effect, perms.Trust)
	}
	return nil
}

// WrapUntrustedInput frames untrusted PR text/comments/instructions in explicit XML-style tags,
// neutralizing closing tag breakouts and NUL bytes so untrusted content cannot escape its boundary.
func WrapUntrustedInput(tag, content string) string {
	trimmed := strings.TrimSpace(strings.ReplaceAll(content, "\x00", ""))
	if trimmed == "" {
		return ""
	}
	safeTag := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' {
			return r
		}
		return '_'
	}, strings.ToLower(tag))
	if safeTag == "" {
		safeTag = "untrusted"
	}
	neutralized := neutralizeTagCI(trimmed, "</"+safeTag, "&lt;/"+safeTag)
	neutralized = neutralizeTagCI(neutralized, "<"+safeTag, "&lt;"+safeTag)
	neutralized = neutralizeTagCI(neutralized, "</untrusted", "&lt;/untrusted")
	return fmt.Sprintf("<%s>\n%s\n</%s>", safeTag, neutralized, safeTag)
}

func neutralizeTagCI(s, target, repl string) string {
	lower := strings.ToLower(s)
	lowerTarget := strings.ToLower(target)
	if !strings.Contains(lower, lowerTarget) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	i := 0
	for i < len(s) {
		idx := strings.Index(lower[i:], lowerTarget)
		if idx == -1 {
			b.WriteString(s[i:])
			break
		}
		b.WriteString(s[i : i+idx])
		b.WriteString(repl)
		i += idx + len(target)
	}
	return b.String()
}
