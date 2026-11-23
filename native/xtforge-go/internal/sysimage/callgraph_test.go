package sysimage

import (
	"reflect"
	"testing"
)

func TestBuildCallGraphBuildsSortedAdjacency(t *testing.T) {
	g := BuildCallGraph([][2]uint64{{1, 2}, {2, 3}, {1, 3}})

	if got, want := g.Callees[1], []uint64{2, 3}; !reflect.DeepEqual(got, want) {
		t.Fatalf("callees[1] = %v, want %v", got, want)
	}
	if got, want := g.Callers[3], []uint64{1, 2}; !reflect.DeepEqual(got, want) {
		t.Fatalf("callers[3] = %v, want %v", got, want)
	}
	if got, want := g.Roots(), []uint64{1}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Roots() = %v, want %v", got, want)
	}
	if got, want := g.Leaves(), []uint64{3}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Leaves() = %v, want %v", got, want)
	}
}

func TestBuildCallGraphGivesEveryAddressEntries(t *testing.T) {
	g := BuildCallGraph([][2]uint64{{1, 2}})

	for _, address := range []uint64{1, 2} {
		if _, ok := g.Callees[address]; !ok {
			t.Errorf("callees has no entry for %d", address)
		}
		if _, ok := g.Callers[address]; !ok {
			t.Errorf("callers has no entry for %d", address)
		}
	}
	if got := len(g.Callers[1]); got != 0 {
		t.Fatalf("callers[1] has length %d, want 0", got)
	}
	if got := len(g.Callees[2]); got != 0 {
		t.Fatalf("callees[2] has length %d, want 0", got)
	}
}

func TestCallGraphIgnoresSelfEdges(t *testing.T) {
	g := BuildCallGraph([][2]uint64{{5, 5}})

	if _, ok := g.Callees[5]; ok {
		t.Error("callees has an entry from a self edge")
	}
	if _, ok := g.Callers[5]; ok {
		t.Error("callers has an entry from a self edge")
	}
	if got := g.Roots(); len(got) != 0 {
		t.Fatalf("Roots() = %v, want empty", got)
	}
	if got := g.Leaves(); len(got) != 0 {
		t.Fatalf("Leaves() = %v, want empty", got)
	}
}

func TestCallGraphCollapsesDuplicateEdges(t *testing.T) {
	g := BuildCallGraph([][2]uint64{{1, 2}, {1, 2}})

	if got := g.Callees[1]; len(got) != 1 || got[0] != 2 {
		t.Fatalf("callees[1] = %v, want [2]", got)
	}
	if got := g.Callers[2]; len(got) != 1 || got[0] != 1 {
		t.Fatalf("callers[2] = %v, want [1]", got)
	}
}

func TestCallGraphEmptyReturnsNonNilSlices(t *testing.T) {
	g := BuildCallGraph(nil)

	if g.Callees == nil || g.Callers == nil {
		t.Fatalf("adjacency maps must be non-nil: %#v", g)
	}
	if got := g.Roots(); got == nil || len(got) != 0 {
		t.Fatalf("Roots() = %#v, want non-nil empty slice", got)
	}
	if got := g.Leaves(); got == nil || len(got) != 0 {
		t.Fatalf("Leaves() = %#v, want non-nil empty slice", got)
	}
}

func TestCallGraphTwoCycleHasNoRootsOrLeaves(t *testing.T) {
	g := BuildCallGraph([][2]uint64{{1, 2}, {2, 1}})

	if got := g.Roots(); len(got) != 0 {
		t.Fatalf("Roots() = %v, want empty", got)
	}
	if got := g.Leaves(); len(got) != 0 {
		t.Fatalf("Leaves() = %v, want empty", got)
	}
}
