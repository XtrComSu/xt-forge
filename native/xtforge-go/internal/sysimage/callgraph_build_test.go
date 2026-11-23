package sysimage

import (
	"debug/elf"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// buildCallGraphELFFixture compiles a tiny static ELF whose main calls helper.
// It skips when clang is missing or cannot link here, since a fixture that
// never built would only make the assertions look green.
func buildCallGraphELFFixture(t *testing.T) string {
	t.Helper()
	clang, err := exec.LookPath("clang")
	if err != nil {
		t.Skip("clang not available: " + err.Error())
	}
	dir := t.TempDir()
	source := filepath.Join(dir, "fixture.c")
	const code = `
__attribute__((noinline)) int helper(int x) { return x + 1; }
int main(void) { return helper(41); }
void _start(void) { (void)main(); __builtin_trap(); }
`
	if err := os.WriteFile(source, []byte(code), 0600); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(dir, "fixture")
	cmd := exec.Command(clang, "-O0", "-fno-pie", "-no-pie", "-nostdlib", "-Wl,-e,_start", source, "-o", binary)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("clang could not build a static ELF fixture: %v: %s", err, output)
	}
	return binary
}

func callGraphFixtureSymbols(t *testing.T, path string) map[string]uint64 {
	t.Helper()
	file, err := elf.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	symbols, err := file.Symbols()
	if err != nil {
		t.Fatal(err)
	}
	out := make(map[string]uint64, len(symbols))
	for _, symbol := range symbols {
		out[symbol.Name] = symbol.Value
	}
	return out
}

func TestCallGraphFromELFFixture(t *testing.T) {
	path := buildCallGraphELFFixture(t)
	symbols := callGraphFixtureSymbols(t, path)
	mainAddress, ok := symbols["main"]
	if !ok {
		t.Fatalf("fixture has no main symbol: %v", symbols)
	}
	helperAddress, ok := symbols["helper"]
	if !ok {
		t.Fatalf("fixture has no helper symbol: %v", symbols)
	}

	result, err := CallGraph(path, "", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if !result.OK {
		t.Fatalf("result is not ok: %#v", result)
	}
	if result.Nodes < 2 {
		t.Fatalf("nodes = %d, want at least 2: %#v", result.Nodes, result)
	}
	if result.Edges < 1 {
		t.Fatalf("edges = %d, want at least 1: %#v", result.Edges, result)
	}
	found := false
	for _, callee := range result.Callees[mainAddress] {
		if callee == helperAddress {
			found = true
		}
	}
	if !found {
		t.Fatalf("helper %#x is not a callee of main %#x: %#v", helperAddress, mainAddress, result.Callees)
	}
}

func TestCallGraphLimitTruncates(t *testing.T) {
	path := buildCallGraphELFFixture(t)
	result, err := CallGraph(path, "", "", 1)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Truncated {
		t.Fatalf("truncated = false, want true: %#v", result)
	}
	if result.Edges > 1 {
		t.Fatalf("edges = %d, want at most 1: %#v", result.Edges, result)
	}
	total := 0
	for _, callees := range result.Callees {
		total += len(callees)
	}
	if total != result.Edges {
		t.Fatalf("callee entries total %d, edges %d", total, result.Edges)
	}
}

func TestCallGraphNonBinaryReturnsError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "notes.txt")
	if err := os.WriteFile(path, []byte("this is not a binary\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := CallGraph(path, "", "", 0); err == nil {
		t.Fatal("CallGraph on a text file returned no error")
	}
}
