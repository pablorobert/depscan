package advisory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pablorobert/depscan/internal/cache"
	"github.com/pablorobert/depscan/internal/model"
)

// realResponse is the exact shape the npm bulk endpoint returns, captured from a live
// call during the design investigation.
const realResponse = `{
  "axios": [
    {
      "id": 1111035,
      "url": "https://github.com/advisories/GHSA-jr5f-v2jv-69x6",
      "title": "axios Requests Vulnerable To Possible SSRF and Credential Leakage via Absolute URL",
      "severity": "high",
      "vulnerable_versions": ">=1.0.0 <1.8.2",
      "cwe": ["CWE-918"],
      "cvss": {"score": 0, "vectorString": null}
    },
    {
      "id": 1118607,
      "url": "https://github.com/advisories/GHSA-q8qp-cvcw-x6jj",
      "title": "Axios has prototype pollution read-side gadgets in HTTP adapter",
      "severity": "moderate",
      "vulnerable_versions": ">=1.0.0 <1.15.2",
      "cwe": ["CWE-1321"],
      "cvss": {"score": 7.4, "vectorString": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N"}
    }
  ],
  "esbuild": [
    {
      "id": 1102341,
      "url": "https://github.com/advisories/GHSA-67mh-4wv8-2f99",
      "title": "esbuild enables any website to send any requests to the development server",
      "severity": "moderate",
      "vulnerable_versions": "<=0.24.2",
      "cwe": ["CWE-346"],
      "cvss": {"score": 5.3, "vectorString": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N"}
    }
  ]
}`

func clientFor(t *testing.T, h http.Handler, offline bool, c *cache.Cache) *Client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return New(Options{BaseURL: srv.URL, Cache: c, Offline: offline, Timeout: 2 * time.Second})
}

func testCache(t *testing.T) *cache.Cache {
	t.Helper()
	c, err := cache.NewAt(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestQueryDecodesWireFormat(t *testing.T) {
	var gotBody map[string][]string
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("content-type = %q", ct)
		}
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &gotBody); err != nil {
			t.Errorf("request body is not the expected map: %v", err)
		}
		fmt.Fprint(w, realResponse)
	})
	client := clientFor(t, h, false, nil)

	res, err := client.Query(context.Background(), map[string][]string{
		"axios":   {"1.6.0"},
		"esbuild": {"0.21.5"},
		"react":   {"18.2.0"},
	})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}

	if len(gotBody) != 3 {
		t.Errorf("request carried %d packages, want 3", len(gotBody))
	}
	if _, ok := res["react"]; ok {
		t.Error("a package with no advisories must be absent, as the endpoint returns it")
	}

	axios := res["axios"]
	if len(axios) != 2 {
		t.Fatalf("axios advisories = %d, want 2", len(axios))
	}
	// Sorted by id, so the ordering is stable across runs.
	if axios[0].ID != 1111035 {
		t.Errorf("first advisory id = %d, want the lowest", axios[0].ID)
	}
	if axios[0].Severity != model.SeverityHigh {
		t.Errorf("severity = %q, want high", axios[0].Severity)
	}
	if axios[0].VulnerableVersions != ">=1.0.0 <1.8.2" {
		t.Errorf("vulnerable versions = %q", axios[0].VulnerableVersions)
	}
	if axios[0].CVSS.VectorString != nil {
		t.Error("a null vectorString must stay null")
	}
	if axios[1].CVSS.Score != 7.4 {
		t.Errorf("cvss score = %v", axios[1].CVSS.Score)
	}
	if len(axios[0].CWE) != 1 || axios[0].CWE[0] != "CWE-918" {
		t.Errorf("cwe = %v", axios[0].CWE)
	}
}

func TestUnknownSeverityIsNormalizedNotInvented(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"pkg":[{"id":1,"severity":"catastrophic","vulnerable_versions":"<1.0.0"}]}`)
	})
	client := clientFor(t, h, false, nil)

	res, err := client.Query(context.Background(), map[string][]string{"pkg": {"0.1.0"}})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if got := res["pkg"][0].Severity; got != model.SeverityUnknown {
		t.Fatalf("severity = %q, want unknown", got)
	}
}

func TestEmptyRequestSkipsTheNetwork(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("no request expected for an empty dependency set")
	})
	client := clientFor(t, h, false, nil)

	res, err := client.Query(context.Background(), nil)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(res) != 0 {
		t.Fatalf("res = %v", res)
	}
}

func TestServerErrorIsRetriedAndTyped(t *testing.T) {
	var calls atomic.Int32
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	client := clientFor(t, h, false, nil)

	_, err := client.Query(context.Background(), map[string][]string{"axios": {"1.6.0"}})
	if err == nil {
		t.Fatal("expected an error")
	}
	if got := calls.Load(); got != 3 {
		t.Fatalf("calls = %d, want 3 attempts", got)
	}

	// The typed error survives the wrapping that records the attempt count.
	var aerr *Error
	if !errors.As(err, &aerr) {
		t.Fatalf("error is not typed: %v", err)
	}
	if aerr.Kind != model.ErrNetwork {
		t.Fatalf("kind = %q, want network", aerr.Kind)
	}
}

func TestClientErrorIsNotRetried(t *testing.T) {
	var calls atomic.Int32
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusBadRequest)
	})
	client := clientFor(t, h, false, nil)

	if _, err := client.Query(context.Background(), map[string][]string{"a": {"1.0.0"}}); err == nil {
		t.Fatal("expected an error")
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("calls = %d, want 1", got)
	}
}

func TestMalformedResponseIsReported(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<html>not json</html>")
	})
	client := clientFor(t, h, false, nil)

	if _, err := client.Query(context.Background(), map[string][]string{"a": {"1.0.0"}}); err == nil {
		t.Fatal("a malformed response must not be read as 'no vulnerabilities'")
	}
}

func TestResponseIsCached(t *testing.T) {
	var calls atomic.Int32
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		fmt.Fprint(w, realResponse)
	})
	client := clientFor(t, h, false, testCache(t))
	req := map[string][]string{"axios": {"1.6.0"}}

	for range 3 {
		if _, err := client.Query(context.Background(), req); err != nil {
			t.Fatalf("Query: %v", err)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("calls = %d, want 1", got)
	}
}

func TestOfflineWithoutCacheIsAnErrorNotAnEmptyResult(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("offline mode must not perform any request")
	})
	client := clientFor(t, h, true, testCache(t))

	_, err := client.Query(context.Background(), map[string][]string{"axios": {"1.6.0"}})
	if err == nil {
		t.Fatal("offline with no cache must fail, never report a clean result")
	}
	var aerr *Error
	if !errors.As(err, &aerr) || aerr.Kind != model.ErrCacheMissOffline {
		t.Fatalf("kind = %v, want cache_miss_offline", err)
	}
}

func TestChunkingIsDeterministicAndBounded(t *testing.T) {
	req := make(map[string][]string)
	for i := range chunkSize + 500 {
		req[fmt.Sprintf("pkg-%04d", i)] = []string{"1.0.0"}
	}

	first := chunks(req)
	second := chunks(req)

	if len(first) != 2 {
		t.Fatalf("chunks = %d, want 2", len(first))
	}
	if len(first[0]) != chunkSize {
		t.Errorf("first chunk = %d packages, want %d", len(first[0]), chunkSize)
	}
	if len(first[1]) != 500 {
		t.Errorf("second chunk = %d packages, want 500", len(first[1]))
	}

	// Stable chunking keeps the cache key of each chunk usable across runs.
	for i := range first {
		if len(first[i]) != len(second[i]) {
			t.Fatal("chunking is not deterministic")
		}
		for name := range first[i] {
			if _, ok := second[i][name]; !ok {
				t.Fatalf("%s moved between chunks across calls", name)
			}
		}
	}
}

func TestChunkedQueryMergesResults(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string][]string
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &body)
		// Answer for whichever package of interest is in this chunk.
		out := map[string][]map[string]any{}
		for name := range body {
			if name == "pkg-0000" || name == "pkg-1200" {
				out[name] = []map[string]any{{
					"id": 1, "severity": "high", "vulnerable_versions": "<2.0.0",
				}}
			}
		}
		_ = json.NewEncoder(w).Encode(out)
	})
	client := clientFor(t, h, false, nil)

	req := make(map[string][]string)
	for i := range chunkSize + 500 {
		req[fmt.Sprintf("pkg-%04d", i)] = []string{"1.0.0"}
	}

	res, err := client.Query(context.Background(), req)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(res["pkg-0000"]) != 1 || len(res["pkg-1200"]) != 1 {
		t.Fatalf("results from both chunks must be merged: %v", res)
	}
}
