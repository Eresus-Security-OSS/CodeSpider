package codeintel

import (
	"sort"
	"strings"
)

func buildCallGraphs(snap *Snapshot) {
	byName := make(map[string][]string)
	for id, sym := range snap.Symbols {
		if sym.Kind == "func" || sym.Kind == "method" {
			byName[sym.Name] = append(byName[sym.Name], id)
		}
	}

	revSet := make(map[string]map[string]struct{})
	for callerID, sym := range snap.Symbols {
		if len(sym.Calls) == 0 {
			continue
		}
		var targets []string
		for _, call := range sym.Calls {
			short := call
			if _, after, ok := strings.Cut(call, "."); ok {
				short = after
			}
			for _, targetID := range byName[short] {
				if targetID == callerID {
					continue
				}
				targets = append(targets, targetID)
				if revSet[targetID] == nil {
					revSet[targetID] = make(map[string]struct{})
				}
				revSet[targetID][callerID] = struct{}{}
			}
		}
		if len(targets) > 0 {
			sort.Strings(targets)
			snap.CallGraph[callerID] = targets
		}
	}

	for targetID, callers := range revSet {
		var list []string
		for c := range callers {
			list = append(list, c)
		}
		sort.Strings(list)
		snap.ReverseCallers[targetID] = list
	}
}

// FindImportCycles returns any package import cycles detected within snap.ImportGraph.
func (s *Snapshot) FindImportCycles() [][]string {
	if s == nil {
		return nil
	}
	const (
		unvisited = 0
		visiting  = 1
		visited   = 2
	)
	state := make(map[string]int)
	var stack []string
	var cycles [][]string

	var dfs func(pkg string)
	dfs = func(pkg string) {
		state[pkg] = visiting
		stack = append(stack, pkg)
		for _, imp := range s.ImportGraph[pkg] {
			// Only track internal package cycles present in Snapshot.Packages
			if _, internal := s.Packages[imp]; !internal {
				continue
			}
			if state[imp] == visiting {
				for i, p := range stack {
					if p == imp {
						cyc := append([]string(nil), stack[i:]...)
						cyc = append(cyc, imp)
						cycles = append(cycles, cyc)
						break
					}
				}
			} else if state[imp] == unvisited {
				dfs(imp)
			}
		}
		stack = stack[:len(stack)-1]
		state[pkg] = visited
	}

	pkgs := make([]string, 0, len(s.Packages))
	for p := range s.Packages {
		pkgs = append(pkgs, p)
	}
	sort.Strings(pkgs)
	for _, p := range pkgs {
		if state[p] == unvisited {
			dfs(p)
		}
	}
	return cycles
}

// ImpactedTests traverses ReverseCallers up to maxHops to find Test* symbols affected by changedSymbolIDs.
func (s *Snapshot) ImpactedTests(changedSymbolIDs []string, maxHops int) []string {
	if s == nil || len(changedSymbolIDs) == 0 {
		return nil
	}
	if maxHops <= 0 {
		maxHops = 3
	}
	visited := make(map[string]bool)
	queue := append([]string(nil), changedSymbolIDs...)
	for _, id := range queue {
		visited[id] = true
	}

	testSet := make(map[string]struct{})
	for hop := 0; hop < maxHops && len(queue) > 0; hop++ {
		var next []string
		for _, cur := range queue {
			if sym, ok := s.Symbols[cur]; ok && strings.HasPrefix(sym.Name, "Test") && strings.HasSuffix(sym.File, "_test.go") {
				testSet[sym.File+":"+sym.Name] = struct{}{}
			}
			for _, caller := range s.ReverseCallers[cur] {
				if !visited[caller] {
					visited[caller] = true
					next = append(next, caller)
				}
			}
		}
		queue = next
	}

	out := make([]string, 0, len(testSet))
	for t := range testSet {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}
