// Package orggraph maintains an incremental, commit-aware cross-repository knowledge graph
// with verified vs. inferred edge confidence, strict per-repo ACL filtering, and speculative merge checks.
package orggraph

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/Eresus-Security-OSS/CodeSpider/internal/codeintel"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/lang"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/policy"
	"github.com/Eresus-Security-OSS/CodeSpider/internal/workspace"
)

// NodeKind classifies nodes in the organization dependency graph.
type NodeKind string

const (
	NodeRepo        NodeKind = "repo"
	NodePackage     NodeKind = "package"
	NodeFunc        NodeKind = "func"
	NodeType        NodeKind = "type"
	NodeAPIContract NodeKind = "api_contract"
	NodeSchema      NodeKind = "schema"
	NodeEvent       NodeKind = "event"
	NodeTest        NodeKind = "test"
	NodeIncident    NodeKind = "incident"
)

// EdgeConfidence separates compiler/import-verified dependencies from heuristic matches.
type EdgeConfidence string

const (
	EdgeVerified EdgeConfidence = "verified"
	EdgeInferred EdgeConfidence = "inferred"
)

// Node represents a symbol, contract, package, repo, test, or incident in the graph.
type Node struct {
	ID         string   `json:"id"`
	Repo       string   `json:"repo"`
	Kind       NodeKind `json:"kind"`
	Name       string   `json:"name"`
	File       string   `json:"file,omitempty"`
	CommitSHA  string   `json:"commit_sha,omitempty"`
	Signature  string   `json:"signature,omitempty"`
	ModulePath string   `json:"module_path,omitempty"`
}

// Edge represents a directed dependency or contract relationship between two nodes.
type Edge struct {
	From       string         `json:"from"`
	To         string         `json:"to"`
	FromRepo   string         `json:"from_repo"`
	ToRepo     string         `json:"to_repo"`
	Relation   string         `json:"relation"` // imports, calls, implements, consumes_contract, tested_by
	Confidence EdgeConfidence `json:"confidence"`
}

// ImpactItem describes one cross-repo consumer impacted by a changed symbol/contract.
type ImpactItem struct {
	Repo       string         `json:"repo"`
	NodeID     string         `json:"node_id"`
	Target     string         `json:"target"`
	Relation   string         `json:"relation"`
	Confidence EdgeConfidence `json:"confidence"`
}

// ImpactReport separates verified from inferred cross-repo impacts after ACL enforcement.
type ImpactReport struct {
	VerifiedImpacts []ImpactItem `json:"verified_impacts,omitempty"`
	InferredImpacts []ImpactItem `json:"inferred_impacts,omitempty"`
}

// SnapshotView is a read-only JSON view of permitted graph nodes and edges.
type SnapshotView struct {
	RepoCommits map[string]string `json:"repo_commits"`
	Nodes       []Node            `json:"nodes"`
	Edges       []Edge            `json:"edges"`
}

type persistedGraph struct {
	RepoCommits map[string]string `json:"repo_commits"`
	Nodes       map[string]Node   `json:"nodes"`
	Edges       []Edge            `json:"edges"`
}

// Graph stores cross-repo nodes and edges with atomic JSON persistence.
type Graph struct {
	mu    sync.RWMutex
	path  string
	state persistedGraph
}

// Open loads or initializes an orggraph store under dataDir.
func Open(dataDir string) (*Graph, error) {
	g := &Graph{
		state: persistedGraph{
			RepoCommits: make(map[string]string),
			Nodes:       make(map[string]Node),
		},
	}
	if dataDir == "" {
		return g, nil
	}
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return nil, err
	}
	g.path = filepath.Join(dataDir, "orggraph.json")
	raw, err := os.ReadFile(g.path)
	if err == nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, &g.state); err != nil {
			return nil, fmt.Errorf("corrupt orggraph %s: %w", g.path, err)
		}
		if g.state.RepoCommits == nil {
			g.state.RepoCommits = make(map[string]string)
		}
		if g.state.Nodes == nil {
			g.state.Nodes = make(map[string]Node)
		}
	} else if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	return g, nil
}

// IndexRepoSnapshot incrementally updates nodes and edges for repoSlug when commitSHA changes.
func (g *Graph) IndexRepoSnapshot(repoSlug, commitSHA string, snap *codeintel.Snapshot, contracts []lang.Contract) error {
	if g == nil || repoSlug == "" {
		return nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()

	if commitSHA != "" && g.state.RepoCommits[repoSlug] == commitSHA {
		return nil // incremental no-op for unchanged commit
	}

	// Remove previous nodes & edges belonging to repoSlug.
	for id, n := range g.state.Nodes {
		if strings.EqualFold(n.Repo, repoSlug) {
			delete(g.state.Nodes, id)
		}
	}
	keptEdges := make([]Edge, 0, len(g.state.Edges))
	for _, e := range g.state.Edges {
		if !strings.EqualFold(e.FromRepo, repoSlug) {
			keptEdges = append(keptEdges, e)
		}
	}
	g.state.Edges = keptEdges

	repoNodeID := "repo:" + repoSlug
	var modPath string
	if snap != nil {
		modPath = snap.ModulePath
	}
	g.state.Nodes[repoNodeID] = Node{
		ID:         repoNodeID,
		Repo:       repoSlug,
		Kind:       NodeRepo,
		Name:       repoSlug,
		CommitSHA:  commitSHA,
		ModulePath: modPath,
	}

	if snap != nil {
		for pkgDir, ps := range snap.Packages {
			pkgID := repoSlug + "::pkg:" + pkgDir
			g.state.Nodes[pkgID] = Node{
				ID: pkgID, Repo: repoSlug, Kind: NodePackage, Name: pkgDir, CommitSHA: commitSHA, ModulePath: modPath,
			}
			for _, imp := range ps.Imports {
				g.state.Edges = append(g.state.Edges, Edge{
					From: pkgID, To: "import:" + imp, FromRepo: repoSlug, ToRepo: inferRepoFromImport(imp),
					Relation: "imports", Confidence: EdgeVerified,
				})
			}
		}
		for id, sym := range snap.Symbols {
			kind := NodeFunc
			if sym.Kind == "struct" || sym.Kind == "interface" || sym.Kind == "type" || sym.Kind == "alias" {
				kind = NodeType
			}
			if strings.HasSuffix(sym.File, "_test.go") && strings.HasPrefix(sym.Name, "Test") {
				kind = NodeTest
			}
			nodeID := repoSlug + "::" + id
			g.state.Nodes[nodeID] = Node{
				ID: nodeID, Repo: repoSlug, Kind: kind, Name: sym.Name, File: sym.File,
				CommitSHA: commitSHA, Signature: sym.Signature, ModulePath: modPath,
			}
			for _, call := range sym.Calls {
				conf := EdgeInferred
				if strings.Contains(call, ".") {
					conf = EdgeVerified
				}
				g.state.Edges = append(g.state.Edges, Edge{
					From: nodeID, To: call, FromRepo: repoSlug, ToRepo: "*",
					Relation: "calls", Confidence: conf,
				})
			}
		}
	}

	for _, c := range contracts {
		cid := fmt.Sprintf("%s::contract:%s:%s", repoSlug, c.Kind, c.Name)
		g.state.Nodes[cid] = Node{
			ID: cid, Repo: repoSlug, Kind: NodeAPIContract, Name: c.Name, File: c.File,
			CommitSHA: commitSHA, Signature: c.Signature,
		}
	}

	if commitSHA != "" {
		g.state.RepoCommits[repoSlug] = commitSHA
	}
	return g.saveLocked()
}

// QueryImpact finds downstream repositories referencing changedSymbols or sourceModule,
// strictly filtering results through perms (CapCrossRepoRead + owner/repo allowlists).
func (g *Graph) QueryImpact(sourceRepo, sourceModule string, changedSymbols []string, perms policy.PermissionSet) ImpactReport {
	var rep ImpactReport
	if g == nil || !perms.Has(policy.CapCrossRepoRead) || len(changedSymbols) == 0 {
		return rep
	}

	symShort := make(map[string]string, len(changedSymbols))
	for _, s := range changedSymbols {
		short := s
		if idx := strings.LastIndex(s, "."); idx != -1 {
			short = s[idx+1:]
		}
		if short != "" {
			symShort[short] = s
		}
	}

	g.mu.RLock()
	defer g.mu.RUnlock()

	seen := make(map[string]bool)
	for _, e := range g.state.Edges {
		if strings.EqualFold(e.FromRepo, sourceRepo) {
			continue
		}
		if !isRepoPermitted(e.FromRepo, perms) {
			continue
		}
		if e.Relation == "imports" && sourceModule != "" && strings.HasPrefix(e.To, "import:"+sourceModule) {
			key := e.From + "->" + e.To
			if !seen[key] {
				seen[key] = true
				rep.VerifiedImpacts = append(rep.VerifiedImpacts, ImpactItem{
					Repo: e.FromRepo, NodeID: e.From, Target: strings.TrimPrefix(e.To, "import:"),
					Relation: "imports", Confidence: EdgeVerified,
				})
			}
			continue
		}
		if e.Relation == "calls" {
			targetShort := e.To
			if idx := strings.LastIndex(e.To, "."); idx != -1 {
				targetShort = e.To[idx+1:]
			}
			if full, ok := symShort[targetShort]; ok {
				key := e.From + "->" + full
				if !seen[key] {
					seen[key] = true
					rep.InferredImpacts = append(rep.InferredImpacts, ImpactItem{
						Repo: e.FromRepo, NodeID: e.From, Target: full,
						Relation: "calls", Confidence: EdgeInferred,
					})
				}
			}
		}
	}
	return rep
}

// View returns a sorted snapshot of nodes and edges filtered by permitted repos (or all if perms is nil).
func (g *Graph) View(perms *policy.PermissionSet) SnapshotView {
	if g == nil {
		return SnapshotView{}
	}
	g.mu.RLock()
	defer g.mu.RUnlock()

	view := SnapshotView{
		RepoCommits: make(map[string]string),
	}
	for r, sha := range g.state.RepoCommits {
		if perms == nil || isRepoPermitted(r, *perms) {
			view.RepoCommits[r] = sha
		}
	}
	for _, n := range g.state.Nodes {
		if perms == nil || isRepoPermitted(n.Repo, *perms) {
			view.Nodes = append(view.Nodes, n)
		}
	}
	for _, e := range g.state.Edges {
		if perms == nil || isRepoPermitted(e.FromRepo, *perms) {
			view.Edges = append(view.Edges, e)
		}
	}
	sort.Slice(view.Nodes, func(i, j int) bool { return view.Nodes[i].ID < view.Nodes[j].ID })
	return view
}

// MergeCheckResult reports whether two PR head commits conflict when speculatively merged.
type MergeCheckResult struct {
	HasConflict   bool     `json:"has_conflict"`
	ConflictFiles []string `json:"conflict_files,omitempty"`
	Detail        string   `json:"detail,omitempty"`
}

// SpeculativeMergeCheck tests merging prASHA and prBSHA inside a disposable detached worktree
// without mutating any branch or cached mirror refs.
func SpeculativeMergeCheck(ctx context.Context, ws *workspace.Manager, owner, repo, cloneURL, prASHA, prBSHA string) (MergeCheckResult, error) {
	if ws == nil || prASHA == "" || prBSHA == "" {
		return MergeCheckResult{}, fmt.Errorf("workspace and both commit SHAs are required")
	}
	wtDir, cleanup, err := ws.CheckoutPRReadOnly(ctx, owner, repo, cloneURL, prASHA)
	if err != nil {
		return MergeCheckResult{}, err
	}
	defer cleanup()

	cmd := exec.CommandContext(ctx, "git",
		"-c", "core.hooksPath=/dev/null",
		"-c", "user.name=CodeSpider",
		"-c", "user.email=codespider@local",
		"merge", "--no-commit", "--no-ff", prBSHA,
	)
	cmd.Dir = wtDir
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	out, mergeErr := cmd.CombinedOutput()
	if mergeErr == nil {
		return MergeCheckResult{HasConflict: false, Detail: "clean speculative merge"}, nil
	}
	var files []string
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "CONFLICT ") {
			files = append(files, strings.TrimSpace(line))
		}
	}
	return MergeCheckResult{
		HasConflict:   true,
		ConflictFiles: files,
		Detail:        strings.TrimSpace(string(out)),
	}, nil
}

func isRepoPermitted(repoSlug string, perms policy.PermissionSet) bool {
	owner, _, _ := strings.Cut(repoSlug, "/")
	if perms.AllowSameOwner && perms.Owner != "" && strings.EqualFold(owner, perms.Owner) {
		return true
	}
	for _, allowed := range perms.AllowedCrossRepo {
		if strings.EqualFold(strings.TrimSpace(allowed), repoSlug) {
			return true
		}
	}
	return false
}

func inferRepoFromImport(imp string) string {
	parts := strings.Split(imp, "/")
	if len(parts) >= 3 && strings.Contains(parts[0], ".") {
		return parts[1] + "/" + parts[2]
	}
	return "*"
}

func (g *Graph) saveLocked() error {
	if g.path == "" {
		return nil
	}
	raw, err := json.MarshalIndent(g.state, "", "  ")
	if err != nil {
		return err
	}
	tmp := g.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, g.path)
}
