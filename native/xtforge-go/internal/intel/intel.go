// Package intel implements keyless threat intelligence lookups in pure Go
// stdlib using concurrent fan-out (NVD 2.0, FIRST EPSS, CISA KEV, Shodan
// InternetDB, GreyNoise Community, CIRCL Hashlookup, and system DNS) with
// disk caching under $XT_HOME/cache/net/ compatible with XT_NET_OFFLINE=1.
package intel

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"xtforge-hub/internal/guard"
)

const (
	userAgent      = "xt-forge/0.4 (+intel)"
	maxResponseB   = 8 << 20
	kevTTL         = 6 * 3600
	nvdTTL         = 24 * 3600
	ipTTL          = 3600
	defaultTimeout = 20 * time.Second
)

var (
	cveRe      = regexp.MustCompile(`(?i)^CVE-\d{4}-\d{4,7}$`)
	hostnameRe = regexp.MustCompile(`(?i)^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)

	// Override points for unit tests.
	baseURLs = map[string]string{
		"internetdb": "https://internetdb.shodan.io",
		"greynoise":  "https://api.greynoise.io/v3/community",
		"nvd":        "https://services.nvd.nist.gov/rest/json/cves/2.0",
		"epss":       "https://api.first.org/data/v1/epss",
		"kev":        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
		"circl":      "https://hashlookup.circl.lu/lookup",
	}

	httpClient = &http.Client{Timeout: defaultTimeout}
)

var sourceDescriptions = map[string]string{
	"internetdb":    "https://internetdb.shodan.io - ports, hostnames, vulns (free)",
	"greynoise":     "https://api.greynoise.io/v3/community - scanning noise (free)",
	"nvd":           "https://services.nvd.nist.gov/rest/json/cves/2.0 - CVE detail (free)",
	"epss":          "https://api.first.org/data/v1/epss - exploit probability (free)",
	"kev":           "https://www.cisa.gov/.../known_exploited_vulnerabilities.json (free)",
	"circl":         "https://hashlookup.circl.lu - known-file lookup (free)",
	"dns":           "system resolver - A, AAAA, MX, NS, TXT, CNAME (free)",
	"virustotal":    "https://www.virustotal.com/api/v3 - needs XT_VT_KEY",
	"malwarebazaar": "https://mb-api.abuse.ch/api/v1 - needs XT_ABUSECH_KEY",
}

var optionalKeys = map[string][]string{
	"virustotal":    {"XT_VT_KEY", "VT_API_KEY", "VIRUSTOTAL_API_KEY"},
	"malwarebazaar": {"XT_ABUSECH_KEY", "ABUSECH_AUTH_KEY"},
}

func envKey(name string) string {
	for _, k := range optionalKeys[name] {
		if v := strings.TrimSpace(os.Getenv(k)); v != "" {
			return v
		}
	}
	return ""
}

func keyStatus() map[string]bool {
	out := make(map[string]bool, len(optionalKeys))
	for name := range optionalKeys {
		out[name] = envKey(name) != ""
	}
	return out
}

func isOffline() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("XT_NET_OFFLINE")))
	return v != "" && v != "0" && v != "false"
}

func cachePath(key string) string {
	sum := sha256.Sum256([]byte(key))
	dir := filepath.Join(guard.XTHome(), "cache", "net")
	_ = os.MkdirAll(dir, 0o755)
	return filepath.Join(dir, hex.EncodeToString(sum[:])[:32]+".json")
}

type cacheEntry struct {
	At      float64 `json:"at"`
	Payload any     `json:"payload"`
}

func getJSON(targetURL string, headers map[string]string, ttlSec int, timeout time.Duration) (bool, any, string) {
	if ttlSec > 0 {
		p := cachePath(targetURL)
		if raw, err := os.ReadFile(p); err == nil {
			var ce cacheEntry
			if json.Unmarshal(raw, &ce) == nil && ce.Payload != nil {
				age := float64(time.Now().Unix()) - ce.At
				if age <= float64(ttlSec) {
					return true, ce.Payload, ""
				}
			}
		}
	}
	if isOffline() {
		return false, nil, "offline mode (XT_NET_OFFLINE=1) with no valid cache"
	}

	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return false, nil, err.Error()
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	client := httpClient
	if timeout > 0 && timeout != httpClient.Timeout {
		client = &http.Client{Timeout: timeout}
	}
	resp, err := client.Do(req)
	if err != nil {
		return false, nil, err.Error()
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseB))
	if err != nil {
		return false, nil, err.Error()
	}
	if resp.StatusCode == 404 {
		return false, nil, "HTTP 404: not found"
	}
	if resp.StatusCode >= 400 {
		return false, nil, fmt.Sprintf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body[:minInt(len(body), 160)])))
	}
	var payload any
	if err := json.Unmarshal(body, &payload); err != nil {
		return false, nil, "invalid JSON: " + err.Error()
	}
	if ttlSec > 0 {
		if encoded, err := json.Marshal(cacheEntry{At: float64(time.Now().Unix()), Payload: payload}); err == nil {
			_ = os.WriteFile(cachePath(targetURL), encoded, 0o644)
		}
	}
	return true, payload, ""
}

// Sources returns the supported threat intelligence feeds and optional API key status.
func Sources() map[string]any {
	ks := keyStatus()
	active := make([]string, 0, len(sourceDescriptions))
	for k, ok := range ks {
		if ok {
			active = append(active, k)
		}
	}
	active = append(active, "internetdb", "greynoise", "nvd", "epss", "kev", "circl", "dns")
	sort.Strings(active)
	return map[string]any{
		"ok":      true,
		"count":   len(sourceDescriptions),
		"sources": sourceDescriptions,
		"keys":    ks,
		"active":  active,
		"engine":  "go",
		"note":    "all free sources need no signup; optional keys join when env vars are set",
	}
}

// IP queries Shodan InternetDB and GreyNoise Community concurrently for a public IP.
func IP(address string) map[string]any {
	val := strings.TrimSpace(address)
	parsed := net.ParseIP(val)
	if parsed == nil {
		return map[string]any{"ok": false, "err": fmt.Sprintf("not an IP address: %q", val)}
	}
	if parsed.IsPrivate() || parsed.IsLoopback() || parsed.IsUnspecified() || parsed.IsLinkLocalUnicast() || parsed.IsMulticast() {
		return map[string]any{"ok": false, "err": "private, loopback or reserved address"}
	}

	canonicalIP := parsed.String()
	sources := map[string]any{}
	var mu sync.Mutex
	var wg sync.WaitGroup

	wg.Add(2)
	go func() {
		defer wg.Done()
		ok, payload, errStr := getJSON(strings.TrimRight(baseURLs["internetdb"], "/")+"/"+canonicalIP, nil, ipTTL, 15*time.Second)
		mu.Lock()
		defer mu.Unlock()
		if ok {
			if m, isMap := payload.(map[string]any); isMap {
				sources["internetdb"] = map[string]any{
					"ports":     m["ports"],
					"hostnames": m["hostnames"],
					"cpes":      m["cpes"],
					"tags":      m["tags"],
					"vulns":     m["vulns"],
				}
			}
		} else {
			sources["internetdb"] = map[string]any{"error": errStr}
		}
	}()

	go func() {
		defer wg.Done()
		ok, payload, errStr := getJSON(strings.TrimRight(baseURLs["greynoise"], "/")+"/"+canonicalIP, nil, ipTTL, 15*time.Second)
		mu.Lock()
		defer mu.Unlock()
		if ok {
			if m, isMap := payload.(map[string]any); isMap {
				sources["greynoise"] = map[string]any{
					"noise":          m["noise"],
					"riot":           m["riot"],
					"classification": m["classification"],
					"name":           m["name"],
					"last_seen":      m["last_seen"],
				}
			}
		} else {
			sources["greynoise"] = map[string]any{"error": errStr}
		}
	}()

	wg.Wait()

	var ports, hostnames, vulns any
	if idb, ok := sources["internetdb"].(map[string]any); ok {
		ports = idb["ports"]
		hostnames = idb["hostnames"]
		vulns = idb["vulns"]
	}
	var flags []string
	if gn, ok := sources["greynoise"].(map[string]any); ok {
		if cls, _ := gn["classification"].(string); cls == "malicious" {
			flags = append(flags, "GreyNoise classifies this IP as malicious")
		}
	}
	if vSlice, ok := vulns.([]any); ok && len(vSlice) > 0 {
		flags = append(flags, fmt.Sprintf("%d CVE(s) reported against exposed services", len(vSlice)))
	}

	return map[string]any{
		"ok":        true,
		"ip":        canonicalIP,
		"ports":     ports,
		"hostnames": hostnames,
		"vulns":     vulns,
		"sources":   sources,
		"flags":     flags,
		"engine":    "go",
	}
}

// CVE concurrently pulls NVD 2.0 detail, FIRST EPSS probability, and CISA KEV listing.
func CVE(cveID string) map[string]any {
	val := strings.ToUpper(strings.TrimSpace(cveID))
	if !cveRe.MatchString(val) {
		return map[string]any{"ok": false, "err": fmt.Sprintf("not a CVE id: %q", val)}
	}

	var (
		nvdDetail map[string]any
		nvdErr    string
		epssRes   = map[string]any{"error": "unavailable"}
		kevRes    = map[string]any{"listed": false}
		wg        sync.WaitGroup
	)

	wg.Add(3)
	go func() {
		defer wg.Done()
		u := strings.TrimRight(baseURLs["nvd"], "/") + "?cveId=" + url.QueryEscape(val)
		ok, payload, errStr := getJSON(u, nil, nvdTTL, 30*time.Second)
		if !ok {
			nvdErr = errStr
			return
		}
		m, _ := payload.(map[string]any)
		vulns, _ := m["vulnerabilities"].([]any)
		if len(vulns) == 0 {
			nvdErr = "not found"
			return
		}
		first, _ := vulns[0].(map[string]any)
		cveObj, _ := first["cve"].(map[string]any)
		nvdDetail = parseNVDEntry(cveObj, val)
	}()

	go func() {
		defer wg.Done()
		u := strings.TrimRight(baseURLs["epss"], "/") + "?cve=" + url.QueryEscape(val)
		ok, payload, errStr := getJSON(u, nil, nvdTTL, 15*time.Second)
		if !ok {
			epssRes = map[string]any{"error": errStr}
			return
		}
		m, _ := payload.(map[string]any)
		rows, _ := m["data"].([]any)
		if len(rows) == 0 {
			epssRes = map[string]any{"error": "not scored"}
			return
		}
		row, _ := rows[0].(map[string]any)
		score, _ := strconv.ParseFloat(fmt.Sprint(row["epss"]), 64)
		pct, _ := strconv.ParseFloat(fmt.Sprint(row["percentile"]), 64)
		epssRes = map[string]any{"score": score, "percentile": pct, "date": row["date"]}
	}()

	go func() {
		defer wg.Done()
		entries, errStr := loadKEVCatalog()
		if errStr != "" {
			kevRes = map[string]any{"error": errStr}
			return
		}
		for _, raw := range entries {
			entry, _ := raw.(map[string]any)
			if strings.EqualFold(fmt.Sprint(entry["cveID"]), val) {
				kevRes = map[string]any{
					"listed":     true,
					"date_added": entry["dateAdded"],
					"due_date":   entry["dueDate"],
					"vendor":     entry["vendorProject"],
					"product":    entry["product"],
					"name":       entry["vulnerabilityName"],
					"ransomware": entry["knownRansomwareCampaignUse"],
				}
				return
			}
		}
	}()

	wg.Wait()

	if nvdDetail == nil {
		return map[string]any{"ok": false, "err": nvdErr, "cve": val, "engine": "go"}
	}

	scores, _ := nvdDetail["scores"].([]map[string]any)
	var primary map[string]any
	if len(scores) > 0 {
		primary = scores[0]
	} else {
		primary = map[string]any{}
	}

	var risk []string
	if listed, _ := kevRes["listed"].(bool); listed {
		risk = append(risk, "known exploited in the wild (CISA KEV)")
	}
	if rw, _ := kevRes["ransomware"].(string); rw == "Known" {
		risk = append(risk, "used in ransomware campaigns")
	}
	if prob, ok := epssRes["score"].(float64); ok && prob >= 0.5 {
		risk = append(risk, fmt.Sprintf("high exploit probability (%.0f%%)", prob*100))
	}

	return map[string]any{
		"ok":          true,
		"cve":         val,
		"description": nvdDetail["description"],
		"severity":    primary["severity"],
		"cvss":        primary["score"],
		"vector":      primary["vector"],
		"all_scores":  scores,
		"published":   nvdDetail["published"],
		"modified":    nvdDetail["modified"],
		"status":      nvdDetail["status"],
		"cwes":        nvdDetail["cwes"],
		"epss":        epssRes,
		"kev":         kevRes,
		"risk":        risk,
		"references":  nvdDetail["references"],
		"engine":      "go",
	}
}

func parseNVDEntry(cveObj map[string]any, fallbackID string) map[string]any {
	desc := ""
	if descs, ok := cveObj["descriptions"].([]any); ok {
		for _, item := range descs {
			d, _ := item.(map[string]any)
			if d["lang"] == "en" {
				desc, _ = d["value"].(string)
				break
			}
		}
	}
	if len(desc) > 1200 {
		desc = desc[:1200]
	}

	var scores []map[string]any
	if metrics, ok := cveObj["metrics"].(map[string]any); ok {
		for _, key := range []string{"cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"} {
			arr, _ := metrics[key].([]any)
			if len(arr) > 0 {
				entry, _ := arr[0].(map[string]any)
				data, _ := entry["cvssData"].(map[string]any)
				ver, _ := data["version"].(string)
				if ver == "" {
					ver = strings.TrimPrefix(key, "cvssMetricV")
				}
				sev := data["baseSeverity"]
				if sev == nil {
					sev = entry["baseSeverity"]
				}
				scores = append(scores, map[string]any{
					"version":  ver,
					"score":    data["baseScore"],
					"severity": sev,
					"vector":   data["vectorString"],
					"type":     entry["type"],
				})
			}
		}
	}

	cweSet := map[string]bool{}
	if weak, ok := cveObj["weaknesses"].([]any); ok {
		for _, w := range weak {
			wm, _ := w.(map[string]any)
			if dl, ok := wm["description"].([]any); ok {
				for _, d := range dl {
					dm, _ := d.(map[string]any)
					if v, _ := dm["value"].(string); strings.HasPrefix(v, "CWE-") {
						cweSet[v] = true
					}
				}
			}
		}
	}
	cwes := make([]string, 0, len(cweSet))
	for k := range cweSet {
		cwes = append(cwes, k)
	}
	sort.Strings(cwes)
	if len(cwes) > 6 {
		cwes = cwes[:6]
	}

	var refs []any
	if rArr, ok := cveObj["references"].([]any); ok {
		for i, r := range rArr {
			if i >= 6 {
				break
			}
			rm, _ := r.(map[string]any)
			if rm["url"] != nil {
				refs = append(refs, rm["url"])
			}
		}
	}

	idStr, _ := cveObj["id"].(string)
	if idStr == "" {
		idStr = fallbackID
	}

	return map[string]any{
		"id":          idStr,
		"description": desc,
		"published":   cveObj["published"],
		"modified":    cveObj["lastModified"],
		"status":      cveObj["vulnStatus"],
		"scores":      scores,
		"cwes":        cwes,
		"references":  refs,
	}
}

func loadKEVCatalog() ([]any, string) {
	ok, payload, errStr := getJSON(baseURLs["kev"], nil, kevTTL, 45*time.Second)
	if !ok {
		return nil, errStr
	}
	m, _ := payload.(map[string]any)
	vulns, _ := m["vulnerabilities"].([]any)
	return vulns, ""
}

// KEV queries the CISA Known Exploited Vulnerabilities catalog newest-first.
func KEV(query string, limit int) map[string]any {
	if limit <= 0 {
		limit = 20
	}
	entries, errStr := loadKEVCatalog()
	if errStr != "" {
		return map[string]any{"ok": false, "err": errStr, "engine": "go"}
	}
	needle := strings.ToLower(strings.TrimSpace(query))
	var matched []map[string]any
	for _, raw := range entries {
		e, _ := raw.(map[string]any)
		if needle != "" {
			var sb strings.Builder
			for _, v := range e {
				sb.WriteString(strings.ToLower(fmt.Sprint(v)))
				sb.WriteByte(' ')
			}
			if !strings.Contains(sb.String(), needle) {
				continue
			}
		}
		matched = append(matched, e)
	}
	sort.Slice(matched, func(i, j int) bool {
		return fmt.Sprint(matched[i]["dateAdded"]) > fmt.Sprint(matched[j]["dateAdded"])
	})
	capN := minInt(limit, len(matched))
	rows := make([]map[string]any, 0, capN)
	for _, e := range matched[:capN] {
		nameStr := fmt.Sprint(e["vulnerabilityName"])
		if len(nameStr) > 110 {
			nameStr = nameStr[:110]
		}
		rows = append(rows, map[string]any{
			"cve":        e["cveID"],
			"vendor":     e["vendorProject"],
			"product":    e["product"],
			"name":       nameStr,
			"added":      e["dateAdded"],
			"ransomware": e["knownRansomwareCampaignUse"],
		})
	}
	var totalCatalog any
	if needle == "" {
		totalCatalog = len(matched)
	}
	return map[string]any{
		"ok":            true,
		"query":         query,
		"matched":       len(matched),
		"total_catalog": totalCatalog,
		"entries":       rows,
		"engine":        "go",
	}
}

// Search performs a keyword query against NVD 2.0 with optional recency window.
func Search(keyword string, limit int, sinceDays int) map[string]any {
	val := strings.TrimSpace(keyword)
	if val == "" {
		return map[string]any{"ok": false, "err": "search needs a keyword"}
	}
	if limit <= 0 {
		limit = 10
	}
	if limit > 50 {
		limit = 50
	}
	u := strings.TrimRight(baseURLs["nvd"], "/") + "?keywordSearch=" + url.QueryEscape(val) + "&resultsPerPage=" + strconv.Itoa(limit)
	clamped := false
	var appliedSince any
	if sinceDays > 0 {
		w := sinceDays
		if w > 120 {
			w = 120
			clamped = true
		}
		appliedSince = w
		now := time.Now().UTC()
		start := now.Add(-time.Duration(w) * 24 * time.Hour)
		const layout = "2006-01-02T15:04:05.000"
		u += "&pubStartDate=" + start.Format(layout) + "&pubEndDate=" + now.Format(layout)
	}

	ok, payload, errStr := getJSON(u, nil, nvdTTL, 40*time.Second)
	if !ok {
		return map[string]any{"ok": false, "err": errStr, "engine": "go"}
	}
	m, _ := payload.(map[string]any)
	vulns, _ := m["vulnerabilities"].([]any)
	rows := make([]map[string]any, 0, len(vulns))
	for _, raw := range vulns {
		item, _ := raw.(map[string]any)
		c, _ := item["cve"].(map[string]any)
		parsed := parseNVDEntry(c, "")
		desc, _ := parsed["description"].(string)
		if len(desc) > 180 {
			desc = desc[:180]
		}
		scores, _ := parsed["scores"].([]map[string]any)
		var sc, sev any
		if len(scores) > 0 {
			sc = scores[0]["score"]
			sev = scores[0]["severity"]
		}
		rows = append(rows, map[string]any{
			"cve":         parsed["id"],
			"score":       sc,
			"severity":    sev,
			"published":   parsed["published"],
			"description": desc,
		})
	}
	if sinceDays > 0 {
		sort.Slice(rows, func(i, j int) bool {
			return fmt.Sprint(rows[i]["published"]) > fmt.Sprint(rows[j]["published"])
		})
	}
	note := ""
	if clamped {
		note = "NVD limits date ranges to 120 days; window clamped"
	}
	return map[string]any{
		"ok":         true,
		"keyword":    val,
		"since_days": appliedSince,
		"clamped":    clamped,
		"total":      m["totalResults"],
		"returned":   len(rows),
		"results":    rows,
		"note":       note,
		"engine":     "go",
	}
}

// Hash queries CIRCL Hashlookup for known-good/OS hashes.
func Hash(value string) map[string]any {
	val := strings.ToLower(strings.TrimSpace(value))
	kind := map[int]string{32: "md5", 40: "sha1", 64: "sha256"}[len(val)]
	isHex := kind != ""
	for i := 0; isHex && i < len(val); i++ {
		c := val[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			isHex = false
		}
	}
	if !isHex {
		return map[string]any{"ok": false, "err": "hash must be hex md5 (32), sha1 (40), or sha256 (64)"}
	}
	u := strings.TrimRight(baseURLs["circl"], "/") + "/" + kind + "/" + val
	ok, payload, errStr := getJSON(u, nil, nvdTTL, 15*time.Second)
	res := map[string]any{
		"ok":     true,
		"hash":   val,
		"kind":   kind,
		"known":  false,
		"engine": "go",
	}
	if ok {
		if m, isMap := payload.(map[string]any); isMap && len(m) > 0 {
			res["known"] = true
			res["circl"] = m
		}
	} else {
		res["circl_error"] = errStr
	}
	return res
}

// Domain resolves DNS records concurrently using the system resolver.
func Domain(name string) map[string]any {
	val := strings.ToLower(strings.TrimSpace(strings.TrimRight(name, ".")))
	if !hostnameRe.MatchString(val) {
		return map[string]any{"ok": false, "err": fmt.Sprintf("not a valid hostname: %q", val)}
	}
	var (
		addrs  []string
		mxList []map[string]any
		nsList []string
		txt    []string
		cname  string
		errs   []string
		mu     sync.Mutex
		wg     sync.WaitGroup
	)
	wg.Add(5)
	go func() {
		defer wg.Done()
		ips, err := net.LookupHost(val)
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			errs = append(errs, "A/AAAA: "+err.Error())
		} else {
			addrs = ips
		}
	}()
	go func() {
		defer wg.Done()
		mxs, err := net.LookupMX(val)
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			errs = append(errs, "MX: "+err.Error())
		} else {
			for _, mx := range mxs {
				mxList = append(mxList, map[string]any{"host": strings.TrimRight(mx.Host, "."), "pref": mx.Pref})
			}
		}
	}()
	go func() {
		defer wg.Done()
		nss, err := net.LookupNS(val)
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			errs = append(errs, "NS: "+err.Error())
		} else {
			for _, ns := range nss {
				nsList = append(nsList, strings.TrimRight(ns.Host, "."))
			}
		}
	}()
	go func() {
		defer wg.Done()
		txts, err := net.LookupTXT(val)
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			errs = append(errs, "TXT: "+err.Error())
		} else {
			txt = txts
		}
	}()
	go func() {
		defer wg.Done()
		cn, err := net.LookupCNAME(val)
		mu.Lock()
		defer mu.Unlock()
		if err == nil {
			cnClean := strings.TrimRight(cn, ".")
			if cnClean != val {
				cname = cnClean
			}
		}
	}()
	wg.Wait()

	var mailPosture []string
	hasSPF := false
	for _, t := range txt {
		if strings.Contains(strings.ToLower(t), "v=spf1") {
			hasSPF = true
			mailPosture = append(mailPosture, "SPF record present")
			break
		}
	}
	if !hasSPF {
		mailPosture = append(mailPosture, "no SPF TXT record observed")
	}

	return map[string]any{
		"ok":           true,
		"domain":       val,
		"addresses":    addrs,
		"nameservers":  nsList,
		"mail":         mxList,
		"mail_posture": mailPosture,
		"txt":          txt,
		"cname":        cname,
		"nxdomain":     len(addrs) == 0 && len(nsList) == 0 && len(errs) > 0,
		"dns_errors":   errs,
		"engine":       "go",
	}
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
