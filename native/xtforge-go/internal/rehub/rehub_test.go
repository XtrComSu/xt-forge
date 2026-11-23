package rehub

import (
	"archive/zip"
	"encoding/binary"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestDecompileReturnsEachRequestedTarget(t *testing.T) {
	for _, tool := range []string{"cc", "objdump"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s unavailable", tool)
		}
	}
	tmp := t.TempDir()
	t.Setenv("XT_ROOTS", tmp)
	source := filepath.Join(tmp, "fixture.c")
	binary := filepath.Join(tmp, "fixture")
	if err := os.WriteFile(source, []byte("int first(int x) { return x+1; }\nint second(int x) { return x*2; }\nint main(void) { return first(second(3)); }\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("cc", "-O0", source, "-o", binary).CombinedOutput(); err != nil {
		t.Fatalf("compile fixture: %v: %s", err, out)
	}

	got := Decompile(binary, "first, second, first", "", "objdump", 40)
	results, ok := got["results"].(map[string]map[string]any)
	if !ok || got["ok"] != true || got["count"] != 2 {
		t.Fatalf("expected two unique targets in a successful batch: %#v", got)
	}
	for _, name := range []string{"first", "second"} {
		if result := results[name]; result["ok"] != true || result["target"] != name {
			t.Errorf("unexpected result for %s: %#v", name, result)
		}
	}
}

func TestInspectASARAndNetcapAndAPK(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("XT_ROOTS", tmp)
	t.Setenv("XT_HOME", filepath.Join(tmp, ".xt"))

	// Build a minimal valid Electron ASAR archive.
	payload := []byte("console.log('hi');")
	idxJSON, _ := json.Marshal(map[string]any{
		"files": map[string]any{
			"app.js":     map[string]any{"size": len(payload), "offset": "0"},
			"app.js.map": map[string]any{"size": 2, "offset": "0"},
		},
	})
	// Align JSON length to 4 bytes for clean offset math
	for len(idxJSON)%4 != 0 {
		idxJSON = append(idxJSON, ' ')
	}
	hdr := make([]byte, 16)
	binary.LittleEndian.PutUint32(hdr[0:4], 4)
	binary.LittleEndian.PutUint32(hdr[4:8], uint32(8+len(idxJSON)))
	binary.LittleEndian.PutUint32(hdr[8:12], uint32(4+len(idxJSON)))
	binary.LittleEndian.PutUint32(hdr[12:16], uint32(len(idxJSON)))

	asarPath := filepath.Join(tmp, "app.asar")
	var blob []byte
	blob = append(blob, hdr...)
	blob = append(blob, idxJSON...)
	blob = append(blob, payload...)
	if err := os.WriteFile(asarPath, blob, 0o644); err != nil {
		t.Fatal(err)
	}

	asarRes := InspectASAR(asarPath, "", 20)
	if asarRes["ok"] != true || asarRes["total_files"] != 2 {
		t.Fatalf("unexpected ASAR result: %+v", asarRes)
	}

	// Build a minimal HAR capture with a secret header.
	harPath := filepath.Join(tmp, "cap.har")
	harData := `{"log":{"entries":[{"request":{"method":"GET","url":"https://api.example.com/v1/me","headers":[{"name":"Authorization","value":"Bearer topsecret"}]},"response":{"status":200,"content":{"size":42,"mimeType":"application/json"}}}]}}`
	if err := os.WriteFile(harPath, []byte(harData), 0o644); err != nil {
		t.Fatal(err)
	}
	netRes := InspectNetcap(harPath, 10)
	if netRes["ok"] != true || netRes["total_entries"] != 1 {
		t.Fatalf("unexpected HAR result: %+v", netRes)
	}

	// Build a minimal APK zip.
	apkPath := filepath.Join(tmp, "demo.apk")
	zf, err := os.Create(apkPath)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(zf)
	w1, _ := zw.Create("AndroidManifest.xml")
	_, _ = w1.Write([]byte("android.permission.INTERNET\x00com.demo.MainActivity\x00"))
	w2, _ := zw.Create("classes.dex")
	_, _ = w2.Write([]byte("dex\n035\x00"))
	_ = zw.Close()
	_ = zf.Close()

	apkRes := InspectAPK(apkPath)
	if apkRes["ok"] != true || apkRes["has_manifest"] != true {
		t.Fatalf("unexpected APK result: %+v", apkRes)
	}
}
