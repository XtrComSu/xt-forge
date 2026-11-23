package mcp

import (
	"reflect"
	"testing"
)

func TestBuildLocalArgvDecompileTargets(t *testing.T) {
	entry := CatalogEntry{Name: "re_decompile", Noun: "re", Verb: "decompile"}
	cases := []struct {
		name string
		args map[string]any
		want string
	}{
		{"ordered targets", map[string]any{"symbols": []any{"0x1010", "helper"}, "symbol": "main"}, "0x1010,helper"},
		{"empty list uses single target", map[string]any{"symbols": []any{}, "symbol": "helper"}, "helper"},
		{"legacy address", map[string]any{"address": "0x1010"}, "0x1010"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.args["path"] = "fixture"
			want := []string{"re", "decompile", "fixture", "--symbol", tc.want}
			if got := buildLocalArgv(entry, nil, tc.args); !reflect.DeepEqual(got, want) {
				t.Fatalf("got %q, want %q", got, want)
			}
		})
	}
}

func TestBuildLocalArgvTestRun(t *testing.T) {
	entry := CatalogEntry{Name: "test_run", Noun: "test"}
	args := map[string]any{"path": "fixture", "pattern": "test_sample*"}
	want := []string{"test", "fixture", "--pattern", "test_sample*"}
	if got := buildLocalArgv(entry, nil, args); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
}
