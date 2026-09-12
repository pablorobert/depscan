package cache

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// newAt builds a cache rooted at dir, bypassing os.UserCacheDir so tests never touch
// the real user cache.
func newAt(t *testing.T, dir string) *Cache {
	t.Helper()
	for _, b := range []string{BucketRegistry, BucketAdvisories} {
		if err := os.MkdirAll(filepath.Join(dir, b), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return &Cache{dir: dir, enabled: true}
}

func TestPutGetRoundTrip(t *testing.T) {
	c := newAt(t, t.TempDir())

	if err := c.Put(BucketRegistry, "dist-tags:@scope/pkg", []byte(`{"latest":"1.2.3"}`), `"abc"`); err != nil {
		t.Fatalf("Put: %v", err)
	}

	e, ok := c.Get(BucketRegistry, "dist-tags:@scope/pkg")
	if !ok {
		t.Fatal("entry not found")
	}
	if string(e.Data) != `{"latest":"1.2.3"}` {
		t.Errorf("data = %s", e.Data)
	}
	if e.ETag != `"abc"` {
		t.Errorf("etag = %q", e.ETag)
	}
	if !e.Fresh() {
		t.Error("a just-written entry must be fresh")
	}
}

func TestDisabledCacheIsANoOp(t *testing.T) {
	c, err := New(false)
	if err != nil {
		t.Fatalf("New(false): %v", err)
	}
	if c.Enabled() {
		t.Fatal("cache should be disabled")
	}
	if err := c.Put(BucketRegistry, "k", []byte("v"), ""); err != nil {
		t.Fatalf("Put on a disabled cache must succeed silently: %v", err)
	}
	if _, ok := c.Get(BucketRegistry, "k"); ok {
		t.Fatal("a disabled cache must never report a hit")
	}
	if c.Dir() != "" {
		t.Fatalf("Dir() = %q, want empty", c.Dir())
	}
}

func TestMissOnUnknownKey(t *testing.T) {
	c := newAt(t, t.TempDir())
	if _, ok := c.Get(BucketRegistry, "never-written"); ok {
		t.Fatal("unexpected hit")
	}
}

func TestCorruptEntryIsTreatedAsMissAndRemoved(t *testing.T) {
	dir := t.TempDir()
	c := newAt(t, dir)

	key := "dist-tags:axios"
	if err := c.Put(BucketRegistry, key, []byte(`{"latest":"1.0.0"}`), ""); err != nil {
		t.Fatal(err)
	}
	path := c.path(BucketRegistry, key)
	if err := os.WriteFile(path, []byte("this is not json"), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, ok := c.Get(BucketRegistry, key); ok {
		t.Fatal("a corrupt entry must be reported as a miss")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("a corrupt entry must be removed so it cannot poison later runs")
	}
}

func TestEmptyDataIsTreatedAsMiss(t *testing.T) {
	c := newAt(t, t.TempDir())
	key := "k"
	if err := os.WriteFile(c.path(BucketRegistry, key),
		[]byte(`{"key":"k","storedAt":"2026-01-01T00:00:00Z","data":null}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, ok := c.Get(BucketRegistry, key); ok {
		t.Fatal("an entry with no payload must be a miss")
	}
}

func TestStaleEntryIsStillReturnedForRevalidation(t *testing.T) {
	c := newAt(t, t.TempDir())
	key := "packument:axios"

	stale := Entry{
		Key:      key,
		StoredAt: time.Now().Add(-2 * TTL),
		ETag:     `"old"`,
		Data:     []byte(`{"versions":{}}`),
	}
	writeEntry(t, c.path(BucketRegistry, key), stale)

	e, ok := c.Get(BucketRegistry, key)
	if !ok {
		t.Fatal("a stale entry must still be returned so its ETag can be reused")
	}
	if e.Fresh() {
		t.Fatal("entry should not be fresh")
	}
	if e.ETag != `"old"` {
		t.Fatalf("etag = %q", e.ETag)
	}
}

func TestKeysWithSlashesCannotEscapeTheBucket(t *testing.T) {
	dir := t.TempDir()
	c := newAt(t, dir)

	key := "../../escape/@scope/pkg"
	if err := c.Put(BucketRegistry, key, []byte("x"), ""); err != nil {
		t.Fatalf("Put: %v", err)
	}
	path := c.path(BucketRegistry, key)
	if filepath.Dir(path) != filepath.Join(dir, BucketRegistry) {
		t.Fatalf("entry landed outside its bucket: %s", path)
	}
	if _, ok := c.Get(BucketRegistry, key); !ok {
		t.Fatal("entry should be readable back")
	}
}

func TestConcurrentPutsDoNotCorrupt(t *testing.T) {
	// Not t.TempDir(): on Windows its cleanup can race with the last rename still
	// settling and fail the test for a reason that has nothing to do with the cache.
	dir, err := os.MkdirTemp("", "depscan-cache-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	c := newAt(t, dir)
	key := "dist-tags:axios"

	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			_ = c.Put(BucketRegistry, key, []byte(`{"latest":"1.0.0"}`), "")
		})
	}
	wg.Wait()

	e, ok := c.Get(BucketRegistry, key)
	if !ok {
		t.Fatal("entry missing after concurrent writes")
	}
	if string(e.Data) != `{"latest":"1.0.0"}` {
		t.Fatalf("data = %s", e.Data)
	}

	// No temporary files may be left behind.
	entries, err := os.ReadDir(filepath.Join(c.dir, BucketRegistry))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".tmp") {
			t.Errorf("temporary file left behind: %s", entry.Name())
		}
	}
}

func writeEntry(t *testing.T, path string, e Entry) {
	t.Helper()
	data, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}
