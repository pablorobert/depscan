package registry

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pablorobert/depscan/internal/cache"
	"github.com/pablorobert/depscan/internal/model"
)

func clientFor(t *testing.T, handler http.Handler, offline bool, c *cache.Cache) (*Client, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return New(Options{
		BaseURL:     srv.URL,
		Cache:       c,
		Offline:     offline,
		Concurrency: 4,
		Timeout:     2 * time.Second,
	}), srv
}

func TestLatestBatch(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/-/package/axios/dist-tags", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"latest":"1.20.0","next":"1.7.0-beta.2"}`)
	})
	// A scoped name arrives percent-encoded, so the path contains a literal %2F.
	mux.HandleFunc("/-/package/@scope%2Fpkg/dist-tags", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"latest":"2.1.0"}`)
	})

	client, _ := clientFor(t, mux, false, nil)
	latest, failures := client.LatestBatch(context.Background(), []string{"axios", "@scope/pkg"})

	if len(failures) != 0 {
		t.Fatalf("failures = %v", failures)
	}
	if latest["axios"] != "1.20.0" {
		t.Errorf("axios latest = %q", latest["axios"])
	}
	if latest["@scope/pkg"] != "2.1.0" {
		t.Errorf("scoped latest = %q, want 2.1.0", latest["@scope/pkg"])
	}
}

func TestLatestMissingDistTagIsAFailureNotAnEmptyAnswer(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"next":"2.0.0-rc.1"}`)
	})
	client, _ := clientFor(t, h, false, nil)

	latest, failures := client.LatestBatch(context.Background(), []string{"weird"})
	if _, ok := latest["weird"]; ok {
		t.Error("a package with no latest dist-tag must not appear as resolved")
	}
	if failures["weird"] == nil {
		t.Error("the failure must be reported")
	}
}

func TestNotFoundIsNotRetried(t *testing.T) {
	var calls atomic.Int32
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusNotFound)
	})
	client, _ := clientFor(t, h, false, nil)

	_, failures := client.LatestBatch(context.Background(), []string{"ghost"})
	if failures["ghost"] == nil {
		t.Fatal("expected a failure")
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("calls = %d, want 1: a 404 is definitive and must not be retried", got)
	}
}

func TestServerErrorIsRetriedThenReported(t *testing.T) {
	var calls atomic.Int32
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	})
	client, _ := clientFor(t, h, false, nil)

	_, failures := client.LatestBatch(context.Background(), []string{"flaky"})
	if failures["flaky"] == nil {
		t.Fatal("expected a failure")
	}
	if got := calls.Load(); got != 3 {
		t.Fatalf("calls = %d, want 3 attempts", got)
	}

	var rerr *Error
	if !errors.As(failures["flaky"], &rerr) || rerr.Kind != model.ErrNetwork {
		t.Fatalf("error kind = %v, want network", failures["flaky"])
	}
}

func TestRetrySucceedsAfterTransientFailure(t *testing.T) {
	var calls atomic.Int32
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		fmt.Fprint(w, `{"latest":"3.0.0"}`)
	})
	client, _ := clientFor(t, h, false, nil)

	latest, failures := client.LatestBatch(context.Background(), []string{"pkg"})
	if len(failures) != 0 {
		t.Fatalf("failures = %v", failures)
	}
	if latest["pkg"] != "3.0.0" {
		t.Fatalf("latest = %q", latest["pkg"])
	}
}

func TestTimeoutIsClassifiedAsTimeout(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(300 * time.Millisecond)
		fmt.Fprint(w, `{"latest":"1.0.0"}`)
	})
	srv := httptest.NewServer(h)
	defer srv.Close()

	client := New(Options{BaseURL: srv.URL, Timeout: 20 * time.Millisecond, Concurrency: 1})
	_, failures := client.LatestBatch(context.Background(), []string{"slow"})

	var rerr *Error
	if !errors.As(failures["slow"], &rerr) {
		t.Fatalf("no typed error: %v", failures["slow"])
	}
	if rerr.Kind != model.ErrTimeout {
		t.Fatalf("kind = %q, want timeout", rerr.Kind)
	}
}

func TestMalformedBodyIsReported(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `not json`)
	})
	client, _ := clientFor(t, h, false, nil)

	_, failures := client.LatestBatch(context.Background(), []string{"bad"})
	if failures["bad"] == nil {
		t.Fatal("a malformed response must be reported, not silently ignored")
	}
}

func TestDistTagsAreCachedAndServedWithoutASecondRequest(t *testing.T) {
	var calls atomic.Int32
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		fmt.Fprint(w, `{"latest":"1.20.0"}`)
	})
	c := testCache(t)
	client, _ := clientFor(t, h, false, c)

	for range 3 {
		if latest, failures := client.LatestBatch(context.Background(), []string{"axios"}); len(failures) != 0 || latest["axios"] != "1.20.0" {
			t.Fatalf("latest = %v, failures = %v", latest, failures)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("calls = %d, want 1: the cache should have served the rest", got)
	}
}

func TestOfflineWithoutCacheReportsCacheMiss(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("offline mode must not perform any request")
	})
	client, _ := clientFor(t, h, true, testCache(t))

	_, failures := client.LatestBatch(context.Background(), []string{"axios"})
	var rerr *Error
	if !errors.As(failures["axios"], &rerr) {
		t.Fatalf("no typed error: %v", failures["axios"])
	}
	if rerr.Kind != model.ErrCacheMissOffline {
		t.Fatalf("kind = %q, want cache_miss_offline", rerr.Kind)
	}
}

func TestOfflineServesFromCache(t *testing.T) {
	c := testCache(t)
	if err := c.Put(cache.BucketRegistry, "dist-tags:axios", []byte(`{"latest":"1.9.9"}`), ""); err != nil {
		t.Fatal(err)
	}

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("offline mode must not perform any request")
	})
	client, _ := clientFor(t, h, true, c)

	latest, failures := client.LatestBatch(context.Background(), []string{"axios"})
	if len(failures) != 0 {
		t.Fatalf("failures = %v", failures)
	}
	if latest["axios"] != "1.9.9" {
		t.Fatalf("latest = %q, want the cached 1.9.9", latest["axios"])
	}
}

func TestVersionsBatchUsesAbbreviatedPackument(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Accept"); got != abbreviatedAccept {
			t.Errorf("Accept = %q, want the abbreviated packument type", got)
		}
		w.Header().Set("ETag", `"v1"`)
		fmt.Fprint(w, `{"dist-tags":{"latest":"1.20.0"},"versions":{"1.6.0":{},"1.18.0":{},"1.20.0":{}}}`)
	})
	client, _ := clientFor(t, h, false, nil)

	versions, failures := client.VersionsBatch(context.Background(), []string{"axios"})
	if len(failures) != 0 {
		t.Fatalf("failures = %v", failures)
	}
	if len(versions["axios"]) != 3 {
		t.Fatalf("versions = %v, want 3", versions["axios"])
	}
}

func TestPackumentRevalidatesWithETag(t *testing.T) {
	var full, notModified int32
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") == `"v1"` {
			atomic.AddInt32(&notModified, 1)
			w.WriteHeader(http.StatusNotModified)
			return
		}
		atomic.AddInt32(&full, 1)
		w.Header().Set("ETag", `"v1"`)
		fmt.Fprint(w, `{"versions":{"1.0.0":{},"2.0.0":{}}}`)
	})

	c := testCache(t)
	client, _ := clientFor(t, h, false, c)

	if _, failures := client.VersionsBatch(context.Background(), []string{"axios"}); len(failures) != 0 {
		t.Fatalf("first fetch failed: %v", failures)
	}

	// Force the cached entry to look stale so the next call revalidates instead of
	// serving straight from the TTL.
	if _, ok := c.Get(cache.BucketRegistry, "packument:axios"); !ok {
		t.Fatal("packument was not cached")
	}
	if err := ageEntry(c, "packument:axios"); err != nil {
		t.Fatal(err)
	}

	versions, failures := client.VersionsBatch(context.Background(), []string{"axios"})
	if len(failures) != 0 {
		t.Fatalf("revalidation failed: %v", failures)
	}
	if len(versions["axios"]) != 2 {
		t.Fatalf("versions after 304 = %v, want the cached pair", versions["axios"])
	}
	if got := atomic.LoadInt32(&notModified); got != 1 {
		t.Errorf("If-None-Match requests = %d, want 1", got)
	}
	if got := atomic.LoadInt32(&full); got != 1 {
		t.Errorf("full downloads = %d, want 1: the 304 must avoid a re-download", got)
	}
}

func TestEscapeName(t *testing.T) {
	cases := map[string]string{
		"axios":      "axios",
		"@scope/pkg": "@scope%2Fpkg",
		"@a/b":       "@a%2Fb",
		"weird name": "weird%20name",
	}
	for in, want := range cases {
		if got := escapeName(in); got != want {
			t.Errorf("escapeName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestEmptyBatchDoesNothing(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("no request expected for an empty batch")
	})
	client, _ := clientFor(t, h, false, nil)

	latest, failures := client.LatestBatch(context.Background(), nil)
	if len(latest) != 0 || len(failures) != 0 {
		t.Fatalf("latest = %v, failures = %v", latest, failures)
	}
}
