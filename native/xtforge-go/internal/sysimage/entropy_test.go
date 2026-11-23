package sysimage

import (
	"math"
	"strings"
	"testing"
)

func TestProfileEntropyAllZero(t *testing.T) {
	p := ProfileEntropy(make([]byte, 8192), 0)
	if math.Abs(p.Overall) > 1e-9 {
		t.Fatalf("Overall = %v, want ~0 for zero fill", p.Overall)
	}
	if p.Class != "low" {
		t.Fatalf("Class = %q, want %q", p.Class, "low")
	}
}

func TestProfileEntropyAllByteValues(t *testing.T) {
	data := make([]byte, 0, 16*256)
	for i := 0; i < 16; i++ {
		for b := 0; b < 256; b++ {
			data = append(data, byte(b))
		}
	}
	p := ProfileEntropy(data, 0)
	if math.Abs(p.Overall-8.0) > 0.01 {
		t.Fatalf("Overall = %v, want ~8.0", p.Overall)
	}
	if p.Class != "very-high" {
		t.Fatalf("Class = %q, want %q", p.Class, "very-high")
	}
}

func TestProfileEntropyASCIIText(t *testing.T) {
	text := strings.Repeat("The quick brown fox jumps over the lazy dog. ", 64)
	p := ProfileEntropy([]byte(text), 0)
	if p.Class != "structured" {
		t.Fatalf("Class = %q, want %q (Overall = %v)", p.Class, "structured", p.Overall)
	}
	if p.Overall < 1.0 || p.Overall >= 6.0 {
		t.Fatalf("Overall = %v, want in [1.0, 6.0)", p.Overall)
	}
}

func TestProfileEntropyEmpty(t *testing.T) {
	for _, data := range [][]byte{nil, {}} {
		p := ProfileEntropy(data, 0)
		if p.Overall != 0 {
			t.Fatalf("Overall = %v, want 0", p.Overall)
		}
		if p.Class != "empty" {
			t.Fatalf("Class = %q, want %q", p.Class, "empty")
		}
		if p.Chunks == nil {
			t.Fatal("Chunks is nil, want non-nil empty slice")
		}
		if len(p.Chunks) != 0 {
			t.Fatalf("len(Chunks) = %d, want 0", len(p.Chunks))
		}
	}
}

func TestProfileEntropyChunkCount(t *testing.T) {
	p := ProfileEntropy(make([]byte, 10000), 4096)
	if len(p.Chunks) != 3 {
		t.Fatalf("len(Chunks) = %d, want 3", len(p.Chunks))
	}
	if p.ChunkSize != 4096 {
		t.Fatalf("ChunkSize = %d, want 4096", p.ChunkSize)
	}
}

func TestProfileEntropyDefaultChunkSize(t *testing.T) {
	for _, chunkSize := range []int{0, -1} {
		p := ProfileEntropy(make([]byte, 8192), chunkSize)
		if p.ChunkSize != 4096 {
			t.Fatalf("ChunkSize = %d for chunkSize %d, want 4096", p.ChunkSize, chunkSize)
		}
		if len(p.Chunks) != 2 {
			t.Fatalf("len(Chunks) = %d for chunkSize %d, want 2", len(p.Chunks), chunkSize)
		}
	}
}

func TestProfileEntropyChunkSizeLargerThanData(t *testing.T) {
	p := ProfileEntropy(make([]byte, 32), 1<<30)
	if len(p.Chunks) != 1 {
		t.Fatalf("len(Chunks) = %d, want 1", len(p.Chunks))
	}
}

func TestProfileEntropyHighClass(t *testing.T) {
	data := make([]byte, 0, 16*128)
	for i := 0; i < 16; i++ {
		for b := 0; b < 128; b++ {
			data = append(data, byte(b))
		}
	}
	p := ProfileEntropy(data, 0)
	if p.Class != "high" {
		t.Fatalf("Class = %q, want %q (Overall = %v)", p.Class, "high", p.Overall)
	}
}

func TestProfileEntropyLargeInputComputesEveryChunk(t *testing.T) {
	data := make([]byte, 100000)
	for i := range data {
		data[i] = byte(i % 37)
	}
	p := ProfileEntropy(data, 1024)
	want := (100000 + 1023) / 1024
	if len(p.Chunks) != want {
		t.Fatalf("len(Chunks) = %d, want %d", len(p.Chunks), want)
	}
	for i, c := range p.Chunks {
		if math.IsNaN(c) || c < 0 || c > 8.0 {
			t.Fatalf("Chunks[%d] = %v, want in [0, 8]", i, c)
		}
	}
}
