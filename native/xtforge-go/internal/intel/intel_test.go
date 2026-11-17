package intel

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestValidationAndOfflineBehavior(t *testing.T) {
	t.Setenv("XT_HOME", t.TempDir())
	t.Setenv("XT_NET_OFFLINE", "1")

	if res := IP("not-an-ip"); res["ok"] != false {
		t.Fatalf("expected invalid ip failure, got %+v", res)
	}
	if res := IP("127.0.0.1"); res["ok"] != false {
		t.Fatalf("expected private ip rejection, got %+v", res)
	}
	if res := CVE("NOT-A-CVE"); res["ok"] != false {
		t.Fatalf("expected invalid CVE rejection, got %+v", res)
	}
	if res := Hash("xyz"); res["ok"] != false {
		t.Fatalf("expected invalid hash rejection, got %+v", res)
	}
	if res := Sources(); res["ok"] != true {
		t.Fatalf("expected sources ok, got %+v", res)
	}
}

func TestConcurrentCVEEnrichmentWithMockServers(t *testing.T) {
	t.Setenv("XT_HOME", t.TempDir())
	t.Setenv("XT_NET_OFFLINE", "")

	nvdSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"vulnerabilities": []any{map[string]any{
				"cve": map[string]any{
					"id":           "CVE-2024-3094",
					"vulnStatus":   "Analyzed",
					"published":    "2024-03-29T00:00:00",
					"lastModified": "2024-04-01T00:00:00",
					"descriptions": []any{map[string]any{"lang": "en", "value": "Synthetic test CVE."}},
					"metrics": map[string]any{
						"cvssMetricV31": []any{map[string]any{
							"type":     "Primary",
							"cvssData": map[string]any{"version": "3.1", "baseScore": 10.0, "baseSeverity": "CRITICAL", "vectorString": "CVSS:3.1/AV:N"},
						}},
					},
					"weaknesses": []any{map[string]any{"description": []any{map[string]any{"value": "CWE-506"}}}},
				},
			}},
		})
	}))
	defer nvdSrv.Close()

	epssSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": []any{map[string]any{"epss": "0.85", "percentile": "0.99", "date": "2026-11-17"}},
		})
	}))
	defer epssSrv.Close()

	kevSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"vulnerabilities": []any{map[string]any{
				"cveID":                      "CVE-2024-3094",
				"vendorProject":              "tukaani",
				"product":                    "xz",
				"vulnerabilityName":          "Backdoor test",
				"dateAdded":                  "2024-03-30",
				"knownRansomwareCampaignUse": "Unknown",
			}},
		})
	}))
	defer kevSrv.Close()

	origNVD, origEPSS, origKEV := baseURLs["nvd"], baseURLs["epss"], baseURLs["kev"]
	baseURLs["nvd"], baseURLs["epss"], baseURLs["kev"] = nvdSrv.URL, epssSrv.URL, kevSrv.URL
	defer func() {
		baseURLs["nvd"], baseURLs["epss"], baseURLs["kev"] = origNVD, origEPSS, origKEV
	}()

	res := CVE("cve-2024-3094")
	if res["ok"] != true || res["cve"] != "CVE-2024-3094" || res["severity"] != "CRITICAL" {
		t.Fatalf("unexpected CVE result: %+v", res)
	}
	kevMap := res["kev"].(map[string]any)
	if kevMap["listed"] != true {
		t.Fatalf("expected KEV listed=true, got %+v", kevMap)
	}
}
