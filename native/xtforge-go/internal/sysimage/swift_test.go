package sysimage

import (
	"math/rand"
	"strings"
	"testing"
)

// Swift demangling tests.
//
// The two documented symbols come from a shipped binary; the malformed table
// and the deterministic random strings below make sure an untrusted symbol name
// is always rejected or decoded safely, never a source of a panic.

func TestDemangleSwift(t *testing.T) {
	for _, tc := range []struct {
		symbol string
		want   string
	}{
		{
			"_$s10Foundation10CocoaErrorV4CodeV16fileReadTooLargeAEvgZ",
			"Foundation.CocoaError.Code.fileReadTooLarge.getter : Swift.Bool",
		},
		{
			"_$s10Foundation10CocoaErrorV4CodeVMa",
			"Foundation.CocoaError.Code.type metadata accessor",
		},
		{
			"$s10Foundation10CocoaErrorV4CodeVMa",
			"Foundation.CocoaError.Code.type metadata accessor",
		},
	} {
		got := DemangleSwift(tc.symbol)
		if !strings.Contains(got, tc.want) {
			t.Errorf("DemangleSwift(%q) = %q, want it to contain %q", tc.symbol, got, tc.want)
		}
	}
}

func TestDemangleSymbols(t *testing.T) {
	symbols := []string{
		"_$s10Foundation10CocoaErrorV4CodeV16fileReadTooLargeAEvgZ",
		"main",
		"$s4main3BoxVySiG",
		"_main",
		"_$ss5printyyF",
		"_$s999X",
	}
	want := []string{
		"Foundation.CocoaError.Code.fileReadTooLarge.getter : Swift.Bool",
		"",
		"main.Box<Swift.Int>",
		"",
		"Swift.print function signature",
		"",
	}
	original := append([]string(nil), symbols...)
	got := DemangleSymbols(symbols)
	if len(got) != len(want) {
		t.Fatalf("DemangleSymbols returned %d results, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("DemangleSymbols()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
	for i := range symbols {
		if symbols[i] != original[i] {
			t.Fatalf("DemangleSymbols modified its input at %d", i)
		}
	}
	if got := DemangleSymbols(nil); len(got) != 0 {
		t.Errorf("DemangleSymbols(nil) = %v, want no results", got)
	}
}

func TestDemangleSwiftRejectsNonSwift(t *testing.T) {
	for _, symbol := range []string{"main", "_main"} {
		if got := DemangleSwift(symbol); got != "" {
			t.Errorf("DemangleSwift(%q) = %q, want empty", symbol, got)
		}
	}
}

func TestDemangleSwiftMalformed(t *testing.T) {
	for _, symbol := range []string{
		"",
		"_$s",
		"_$s999X",
		"_$s09Bad",
		"_$s0",
		"_$s4Test",
		"_$s4TestXQ",
		"_$s-4TestV",
		"_$s4TesV",
		"_$s4main3BoxVy",
		"_$s4mainG",
		"_$s4main3BoxVySi",
	} {
		if got := DemangleSwift(symbol); got != "" {
			t.Errorf("DemangleSwift(%q) = %q, want empty", symbol, got)
		}
	}
}

// TestDemangleSwiftFuzzishNoPanic is a deterministic fuzz-ish sweep: arbitrary
// byte strings, with and without Swift prefixes, must never panic. A panic
// fails the test on its own, so the call needs no further assertion.
func TestDemangleSwiftFuzzishNoPanic(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	alphabet := []byte("0123456789ABCXYZSTVMaCgOfpsZ_$Sabcdefghijklmnopqrstuvwxyz")
	for i := 0; i < 10000; i++ {
		buf := make([]byte, rng.Intn(48))
		for j := range buf {
			buf[j] = alphabet[rng.Intn(len(alphabet))]
		}
		raw := string(buf)
		DemangleSwift(raw)
		DemangleSwift("_$s" + raw)
		DemangleSwift("$s" + raw)
		DemangleSwift("_$S" + raw)
		DemangleSwift("$S" + raw)
	}
}

// TestDemangleSwiftWidened covers the generic, standard-library-module and
// function-signature forms, together with truncated manglings that must be
// rejected without panicking.
func TestDemangleSwiftWidened(t *testing.T) {
	for _, tc := range []struct {
		symbol string
		want   string
	}{
		{"_$s4main3BoxVySiG", "main.Box<Swift.Int>"},
		{"_$s4main3BoxVySsG", "main.Box<Swift.String>"},
		{"_$s4main3BoxVySbSdSfSuSvG", "main.Box<Swift.Bool, Swift.Double, Swift.Float, Swift.UInt, Swift.Void>"},
		{"_$s4main3BoxVy2SiSsG", "main.Box<Swift.Int, Swift.String>"},
		{"_$s4main3BoxVG1Si", "main.Box<Swift.Int>"},
		{"_$s4main3BoxVy3FooG", "main.Box<Foo>"},
		{"_$ss3BoxVySiG", "Swift.Box<Swift.Int>"},
		{"_$ss5printyyF", "Swift.print function signature"},
		{"_$s4main1fF", "main.f function signature"},
		{"_$s4main1fyyF", "main.f function signature"},
		{"_$s4main1f_yyF", "main.f function signature"},
		// Malformed: no argument list, no terminator, no children, extra
		// trailing bytes, bad counts and truncated substitutions.
		{"_$s4main3BoxVy", ""},
		{"_$s4mainG", ""},
		{"_$s4main3BoxVySi", ""},
		{"_$s4main3BoxVyG", ""},
		{"_$s4main3BoxVySiGx", ""},
		{"_$s4main3BoxVG0", ""},
		{"_$s4main3BoxVG2Si", ""},
		{"_$s4main3BoxVySi999999999999999999999G", ""},
		{"_$ss", ""},
		{"_$s4main1fyy", ""},
	} {
		got := DemangleSwift(tc.symbol)
		if got != tc.want {
			t.Errorf("DemangleSwift(%q) = %q, want %q", tc.symbol, got, tc.want)
		}
	}
}

// TestDemangleSwiftSubstitutionsAndWrappers covers the widened substitution
// table, protocol/extension context nodes and the optional/tuple wrappers.
// An empty contains field means the result must match want exactly.
func TestDemangleSwiftSubstitutionsAndWrappers(t *testing.T) {
	for _, tc := range []struct {
		symbol   string
		want     string
		contains string
	}{
		{"_$s4main3BoxVySgG", "", "Box<"},
		{"_$s4main3BoxVySi_SitG", "", "("},
		{"_$s4main3BoxVySSG", "main.Box<Swift.Substring>", ""},
		{"_$s4main3BoxVySZG", "", ""},
		{"_$s4main3BoxVyq", "", ""},
		{"_$s4main3BoxVyt", "", ""},
		{"_$s4main3BoxVySz9", "", ""},
		// Remaining substitutions and both wrapper spellings.
		{"_$s4main3BoxVySoShSDSqSnG", "main.Box<Swift.AnyObject, Swift.Set, Swift.Dictionary, Swift.Optional, Swift.Numeric>", ""},
		{"_$s4main3BoxVySaG", "main.Box<Swift.Array>", ""},
		{"_$s4main3BoxVySvSuG", "main.Box<Swift.Void, Swift.UInt>", ""},
		{"_$s4main3BoxVyqSiG", "main.Box<Swift.Int?>", ""},
		{"_$s4main3BoxVyt2SiSsG", "main.Box<(Swift.Int, Swift.String)>", ""},
		// Protocol/extension context nodes in front of a type node.
		{"_$s4main3BoxPVySiG", "main.Box<Swift.Int>", ""},
		{"_$s4main3BoxEVySiG", "main.Box<Swift.Int>", ""},
		{"_$s4mainP3FooVySiG", "main.Foo<Swift.Int>", ""},
	} {
		got := DemangleSwift(tc.symbol)
		if tc.contains != "" {
			if got == "" || !strings.Contains(got, tc.contains) {
				t.Errorf("DemangleSwift(%q) = %q, want a non-empty string containing %q", tc.symbol, got, tc.contains)
			}
			continue
		}
		if got != tc.want {
			t.Errorf("DemangleSwift(%q) = %q, want %q", tc.symbol, got, tc.want)
		}
	}
}

func TestDemangleSwiftSuffixes(t *testing.T) {
	for _, tc := range []struct {
		symbol string
		want   string
	}{
		{"_$s4TestV", "Test struct"},
		{"_$s4TestC", "Test class"},
		{"_$s4TestO", "Test enum"},
		{"_$s4TestP", "Test protocol"},
		{"_$s4TestM", "Test metatype"},
		{"_$s4TestMa", "Test.type metadata accessor"},
		{"_$s4Test1pvgZ", "Test.p static getter"},
		{"_$s4Test1pvg", "Test.p getter"},
		{"_$s4Testf", "Test function"},
	} {
		got := DemangleSwift(tc.symbol)
		if !strings.Contains(got, tc.want) {
			t.Errorf("DemangleSwift(%q) = %q, want it to contain %q", tc.symbol, got, tc.want)
		}
	}
}
