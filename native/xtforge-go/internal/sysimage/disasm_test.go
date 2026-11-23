package sysimage

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDecodeDirectTargets(t *testing.T) {
	cases := []struct {
		arch  string
		bytes []byte
		kind  string
		dest  uint64
	}{
		{"x86_64", []byte{0xe8, 0xfb, 0xff, 0xff, 0xff}, "call", 0x1000},
		{"x86_64", []byte{0x75, 0x02}, "conditional", 0x1004},
		{"arm64", []byte{0x02, 0, 0, 0x94}, "call", 0x1008},
		{"arm64", []byte{0x40, 0, 0, 0x54}, "conditional", 0x1008},
	}
	for _, tc := range cases {
		got, err := decodeInstruction(tc.arch, 0x1000, tc.bytes)
		if err != nil || got.Kind != tc.kind || got.Target == nil || *got.Target != tc.dest || got.Size != len(tc.bytes) {
			t.Errorf("%s %x: %#v, error: %v", tc.arch, tc.bytes, got, err)
		}
	}
}

func TestDecodePCRelativeData(t *testing.T) {
	got, err := decodeInstruction("x86_64", 0x1000, []byte{0x48, 0x8d, 0x05, 9, 0, 0, 0})
	if err != nil || len(got.References) != 1 || got.References[0].Address != 0x1010 || got.Target != nil {
		t.Fatalf("expected data reference without a branch: %#v, %v", got, err)
	}
}

func TestFlowSkipsUnreachableBytes(t *testing.T) {
	// JNE reaches the last RET. The fallthrough makes a call then jumps over
	// invalid bytes. The helper call target lies outside the selected range.
	data := []byte{0x75, 0x09, 0xe8, 0x20, 0, 0, 0, 0xeb, 0x02, 0x0f, 0xff, 0xc3}
	instructions, blocks, warnings := recoverFlow("x86_64", 0x1000, data, 20)
	if len(warnings) != 0 || len(instructions) != 4 || len(blocks) != 3 {
		t.Fatalf("unexpected flow: instructions=%#v blocks=%#v warnings=%v", instructions, blocks, warnings)
	}
	if blocks[1].Address != 0x1002 || len(blocks[1].Edges) != 2 ||
		blocks[1].Edges[0].Kind != "call" || blocks[1].Edges[0].Internal ||
		blocks[1].Edges[1].Kind != "jump" || !blocks[1].Edges[1].Internal {
		t.Fatalf("unexpected edges: %#v", blocks[1])
	}
}

func TestNativeArm64FlowInMachO(t *testing.T) {
	data := machFixture()
	copy(data[0x100:], []byte{
		0x40, 0, 0, 0x34, // cbz w0, entry+8
		0xc0, 3, 0x5f, 0xd6, // ret
		0xc0, 3, 0x5f, 0xd6, // ret
	})
	path := filepath.Join(t.TempDir(), "fixture")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	got, err := Disassemble(path, DisassemblyOptions{Flow: true, Bytes: 12})
	if err != nil || !got.OK || got.Mode != "flow" || len(got.Instructions) != 3 || len(got.Blocks) != 3 {
		t.Fatalf("unexpected flow: %#v, error: %v", got, err)
	}
	branch := got.Blocks[0].Edges
	if len(branch) != 2 || branch[0].Target == nil || *branch[0].Target != got.Address+8 ||
		branch[1].Target == nil || *branch[1].Target != got.Address+4 ||
		!branch[0].Internal || !branch[1].Internal {
		t.Fatalf("unexpected branch edges: %#v", branch)
	}
}
