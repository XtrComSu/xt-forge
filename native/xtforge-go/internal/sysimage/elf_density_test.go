package sysimage

import (
	"os"
	"testing"
)

// ELF function-discovery density.
//
// The descent and gap-scan passes were wired for sparse ELF on 2026-11-23 and the result
// rests on a one-off measurement: libgfortran 2529 -> 7610 functions (437 bytes of
// executable code per function) and the 81 MB opencode binary 50670 -> 70680 (1157 B/fn).
// Nothing re-checked it afterwards, so this pins the bands the same way the PE test pins
// 45..140 B/fn against Ghidra.
//
// The bands are deliberately wide enough not to fail on a different machine's build of the
// same library, and tight enough to catch a rule change that halves or doubles the index.
func TestELFFunctionDensity(t *testing.T) {
	cases := []struct {
		path       string
		minFuncs   int
		maxFuncs   int
		minPerByte float64
		maxPerByte float64
		minNamed   int
	}{
		{"/usr/lib/libgfortran.so.5.0.0", 5000, 20000, 200, 900, 1500},
		{"/usr/bin/opencode", 40000, 150000, 500, 2500, 600},
	}
	checked := 0
	for _, tc := range cases {
		if _, err := os.Stat(tc.path); err != nil {
			t.Logf("%s not installed, skipped", tc.path)
			continue
		}
		overview, err := Overview(tc.path, "")
		if err != nil {
			t.Fatalf("%s: %v", tc.path, err)
		}
		var executable uint64
		for _, region := range overview.Images[0].Executable {
			executable += region.Size
		}
		if executable == 0 {
			t.Fatalf("%s: no executable bytes reported", tc.path)
		}
		result, err := Functions(tc.path, "", "", 200000)
		if err != nil {
			t.Fatalf("%s: %v", tc.path, err)
		}
		functions := result.Images[0].Functions
		total := result.Images[0].Total
		named := 0
		for _, function := range functions {
			if function.Name != "" {
				named++
			}
		}
		perFunction := float64(executable) / float64(total)
		t.Logf("%s: %d executable bytes, %d functions, %.0f B/fn, %d named",
			tc.path, executable, total, perFunction, named)
		if total < tc.minFuncs || total > tc.maxFuncs {
			t.Errorf("%s: %d functions outside %d..%d", tc.path, total, tc.minFuncs, tc.maxFuncs)
		}
		if perFunction < tc.minPerByte || perFunction > tc.maxPerByte {
			t.Errorf("%s: %.0f B/fn outside %.0f..%.0f", tc.path, perFunction,
				tc.minPerByte, tc.maxPerByte)
		}
		if named < tc.minNamed {
			t.Errorf("%s: only %d named functions, want at least %d", tc.path, named, tc.minNamed)
		}
		checked++
	}
	if checked == 0 {
		t.Skip("no large ELF sample on this machine")
	}
}
