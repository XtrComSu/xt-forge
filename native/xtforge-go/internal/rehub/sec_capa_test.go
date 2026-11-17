package rehub

import (
	"os"
	"path/filepath"
	"testing"
)

func TestChecksecAndCapaOnELFAndStrings(t *testing.T) {
	shPath := "/bin/sh"
	if _, err := os.Stat(shPath); err == nil {
		res := Checksec(shPath)
		if res["ok"] != true || res["format"] != "elf" {
			t.Fatalf("unexpected Checksec /bin/sh: %+v", res)
		}
		mits := res["mitigations"].(map[string]any)
		if _, exists := mits["nx"]; !exists {
			t.Fatalf("missing nx field in ELF checksec: %+v", mits)
		}
	}

	tmp := t.TempDir()
	t.Setenv("XT_ROOTS", tmp)
	sample := filepath.Join(tmp, "sample.bin")
	if err := os.WriteFile(sample, []byte("MZ\x00\x00BeingDebugged\x00SeDebugPrivilege\x00"), 0o644); err != nil {
		t.Fatal(err)
	}
	capaRes := Capa(sample)
	if capaRes["ok"] != true {
		t.Fatalf("Capa failed: %+v", capaRes)
	}
	if capaRes["count"].(int) < 2 {
		t.Fatalf("expected >=2 capabilities matched via strings, got %+v", capaRes)
	}
}
