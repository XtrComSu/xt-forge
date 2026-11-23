package sysimage

// CallGraphResult is a call graph recovered from a binary's direct call edges.
type CallGraphResult struct {
	OK        bool                `json:"ok"`
	Engine    string              `json:"engine"`
	Path      string              `json:"path"`
	Format    string              `json:"format"`
	Arch      string              `json:"arch"`
	Nodes     int                 `json:"nodes"`
	Edges     int                 `json:"edges"`
	Roots     []uint64            `json:"roots"`
	Leaves    []uint64            `json:"leaves"`
	Callees   map[uint64][]uint64 `json:"callees,omitempty"`
	Truncated bool                `json:"truncated"`
}

// CallGraph builds the graph of direct calls between indexed functions.
//
// References is the existing analysis entry point for call edges: it indexes
// functions, scans them with the shared flow recovery, and reports each call
// with its source and target. Reusing its results keeps the graph in step with
// `re xrefs-native` and avoids decoding instructions a second time.
func CallGraph(filename, member, arch string, limit int) (CallGraphResult, error) {
	if limit <= 0 {
		limit = maxReferenceOutput
	}
	limit = min(limit, maxReferenceOutput)

	index, err := References(filename, ReferenceOptions{
		Member: member,
		Arch:   arch,
		Limit:  maxReferenceOutput,
	})
	if err != nil {
		return CallGraphResult{}, err
	}
	out := CallGraphResult{
		OK: true, Engine: index.Engine, Path: index.Path, Format: index.Format,
		Arch: index.Arch, Roots: []uint64{}, Leaves: []uint64{},
	}

	edges := make([][2]uint64, 0, len(index.References))
	for _, ref := range index.References {
		// scanReferences only walks indexed functions, so the source is known.
		// add() fills TargetSource from the function index; an empty value means
		// the target was an external or otherwise unindexed address.
		if ref.Kind != "call" || ref.TargetSource == "" || ref.Function == ref.Target {
			continue
		}
		edges = append(edges, [2]uint64{ref.Function, ref.Target})
	}
	// Truncated reports a hit on either cap: more eligible edges than the
	// caller asked for, or more references than the analysis was allowed to
	// collect (those may contain further call edges).
	truncated := len(edges) > limit || index.TotalReferences > len(index.References)
	if len(edges) > limit {
		edges = edges[:limit]
	}

	graph := BuildCallGraph(edges)
	out.Callees = graph.Callees
	out.Nodes = len(graph.Callees)
	for _, callees := range graph.Callees {
		out.Edges += len(callees)
	}
	out.Roots = graph.Roots()
	out.Leaves = graph.Leaves()
	out.Truncated = truncated
	return out, nil
}
