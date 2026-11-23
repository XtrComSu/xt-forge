package sysimage

import "sort"

// CallGraphAdjacency is an adjacency view over a recovered function index.
type CallGraphAdjacency struct {
	Callees map[uint64][]uint64 `json:"callees"`
	Callers map[uint64][]uint64 `json:"callers"`
}

// BuildCallGraph builds caller/callee adjacency from edges.
// Edges are (from, to) pairs. Self edges are ignored, duplicate edges are
// collapsed, and any address appearing only as a caller still gets entries.
func BuildCallGraph(edges [][2]uint64) CallGraphAdjacency {
	g := CallGraphAdjacency{
		Callees: make(map[uint64][]uint64),
		Callers: make(map[uint64][]uint64),
	}
	seen := make(map[[2]uint64]struct{}, len(edges))
	ensure := func(address uint64) {
		if _, ok := g.Callees[address]; !ok {
			g.Callees[address] = []uint64{}
			g.Callers[address] = []uint64{}
		}
	}
	for _, edge := range edges {
		from, to := edge[0], edge[1]
		if from == to {
			continue
		}
		if _, ok := seen[edge]; ok {
			continue
		}
		seen[edge] = struct{}{}
		ensure(from)
		ensure(to)
		g.Callees[from] = append(g.Callees[from], to)
		g.Callers[to] = append(g.Callers[to], from)
	}
	for _, callees := range g.Callees {
		sort.Slice(callees, func(i, j int) bool { return callees[i] < callees[j] })
	}
	for _, callers := range g.Callers {
		sort.Slice(callers, func(i, j int) bool { return callers[i] < callers[j] })
	}
	return g
}

// Roots returns function addresses that call but are never called — the entry
// points of the graph — sorted ascending.
func (g CallGraphAdjacency) Roots() []uint64 {
	roots := make([]uint64, 0)
	for address, callees := range g.Callees {
		if len(callees) > 0 && len(g.Callers[address]) == 0 {
			roots = append(roots, address)
		}
	}
	sort.Slice(roots, func(i, j int) bool { return roots[i] < roots[j] })
	return roots
}

// Leaves returns function addresses that are called but never call — the sink
// ends of the graph — sorted ascending.
func (g CallGraphAdjacency) Leaves() []uint64 {
	leaves := make([]uint64, 0)
	for address, callers := range g.Callers {
		if len(callers) > 0 && len(g.Callees[address]) == 0 {
			leaves = append(leaves, address)
		}
	}
	sort.Slice(leaves, func(i, j int) bool { return leaves[i] < leaves[j] })
	return leaves
}
