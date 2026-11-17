package rehub

import (
	"archive/zip"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

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
