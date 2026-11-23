package sysimage

import (
	"os"
	"testing"
)

// Function output limits.
//
// The cap used to be 2000 and was applied with min(), so a caller asking for 50000 still
// received 2000 — a binary reporting a total of 50,670 could never deliver it. This test
// pins that a requested limit below the cap is honoured exactly.

func TestFunctionsRespectsRequestedLimit(t *testing.T) {
	path := "/bin/ls"
	if _, err := os.Stat(path); err != nil {
		t.Skip("/bin/ls not available")
	}
	full, err := Functions(path, "", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	total := full.Images[0].Total
	if total < 20 {
		t.Skipf("only %d functions; too few to test limiting", total)
	}

	// A limit below the total must return exactly that many and mark the result truncated.
	want := total / 2
	limited, err := Functions(path, "", "", want)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(limited.Images[0].Functions); got != want {
		t.Errorf("limit %d returned %d functions", want, got)
	}
	if !limited.Images[0].Truncated {
		t.Error("a capped result must be marked truncated")
	}

	// A limit above the total must return everything and not claim truncation.
	roomy, err := Functions(path, "", "", total+1000)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(roomy.Images[0].Functions); got != total {
		t.Errorf("limit total+1000 returned %d of %d", got, total)
	}
	if roomy.Images[0].Truncated {
		t.Error("a complete result must not be marked truncated")
	}
}
