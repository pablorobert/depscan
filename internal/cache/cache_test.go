package cache

import (
	"bytes"
	"encoding/json"
	"fmt"
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

// writeEntry writes an entry the way Put would, compressing the payload first.
func writeEntry(t *testing.T, path string, e Entry) {
	t.Helper()
	packed, err := compress(e.Data)
	if err != nil {
		t.Fatal(err)
	}
	e.Data = packed
	data, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestPayloadIsStoredCompressed(t *testing.T) {
	dir := t.TempDir()
	c := newAt(t, dir)

	// A packument-shaped payload: highly repetitive, which is why compression pays.
	var sb strings.Builder
	sb.WriteString(`{"versions":{`)
	for i := range 2000 {
		if i > 0 {
			sb.WriteString(",")
		}
		fmt.Fprintf(&sb, `"1.0.%d":{"dist":{"tarball":"https://registry.npmjs.org/p/-/p-1.0.%d.tgz"}}`, i, i)
	}
	sb.WriteString("}}")
	payload := []byte(sb.String())

	key := "packument:big"
	if err := c.Put(BucketRegistry, key, payload, `"v1"`); err != nil {
		t.Fatalf("Put: %v", err)
	}

	onDisk, err := os.Stat(c.path(BucketRegistry, key))
	if err != nil {
		t.Fatal(err)
	}
	if onDisk.Size() >= int64(len(payload)) {
		t.Fatalf("stored %d bytes for a %d byte payload; it is not being compressed",
			onDisk.Size(), len(payload))
	}

	// Get must hand back the original bytes, inflated.
	e, ok := c.Get(BucketRegistry, key)
	if !ok {
		t.Fatal("entry not found")
	}
	if !bytes.Equal(e.Data, payload) {
		t.Fatal("the payload did not survive the compression round trip")
	}
	if e.ETag != `"v1"` {
		t.Errorf("etag = %q", e.ETag)
	}
}

func TestUncompressedEntryIsDroppedAndRefetched(t *testing.T) {
	dir := t.TempDir()
	c := newAt(t, dir)
	key := "packument:legacy"

	// An entry as an older depscan wrote it: valid envelope, raw payload.
	raw, err := json.Marshal(Entry{Key: key, StoredAt: time.Now(), Data: []byte(`{"versions":{}}`)})
	if err != nil {
		t.Fatal(err)
	}
	path := c.path(BucketRegistry, key)
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}

	if _, ok := c.Get(BucketRegistry, key); ok {
		t.Fatal("a payload that will not inflate must be reported as a miss")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("the unusable entry must be removed so the next run refetches it")
	}
}

func TestInspectReportsSizeBucketsAndHeaviestEntries(t *testing.T) {
	dir := t.TempDir()
	c := newAt(t, dir)

	if err := c.Put(BucketRegistry, "dist-tags:small", []byte(`{"latest":"1.0.0"}`), ""); err != nil {
		t.Fatal(err)
	}
	big := bytes.Repeat([]byte("packument payload "), 4000)
	if err := c.Put(BucketRegistry, "packument:heavy", big, ""); err != nil {
		t.Fatal(err)
	}
	if err := c.Put(BucketAdvisories, "bulk:abc", []byte(`{}`), ""); err != nil {
		t.Fatal(err)
	}

	st, err := Inspect(dir, 5)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if !st.Exists {
		t.Fatal("cache should exist")
	}
	if st.Entries != 3 {
		t.Fatalf("entries = %d, want 3", st.Entries)
	}
	if st.Bytes <= 0 {
		t.Fatal("byte total should be positive")
	}

	byName := map[string]BucketStats{}
	for _, b := range st.Buckets {
		byName[b.Name] = b
	}
	if byName[BucketRegistry].Entries != 2 {
		t.Errorf("registry bucket = %+v, want 2 entries", byName[BucketRegistry])
	}
	if byName[BucketAdvisories].Entries != 1 {
		t.Errorf("advisories bucket = %+v, want 1 entry", byName[BucketAdvisories])
	}

	if len(st.Largest) == 0 {
		t.Fatal("no heaviest entries reported")
	}
	// The heaviest entry is named by its key, not by the hashed filename.
	if st.Largest[0].Key != "packument:heavy" {
		t.Fatalf("heaviest entry = %q, want packument:heavy", st.Largest[0].Key)
	}
}

func TestInspectOnMissingDirectory(t *testing.T) {
	st, err := Inspect(filepath.Join(t.TempDir(), "never-created"), 5)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if st.Exists || st.Entries != 0 {
		t.Fatalf("stats = %+v, want an empty report", st)
	}
}

func TestCleanRemovesEverythingAndReportsIt(t *testing.T) {
	dir := t.TempDir()
	c := newAt(t, dir)
	if err := c.Put(BucketRegistry, "dist-tags:axios", []byte(`{"latest":"1.0.0"}`), ""); err != nil {
		t.Fatal(err)
	}

	freed, entries, err := Clean(dir)
	if err != nil {
		t.Fatalf("Clean: %v", err)
	}
	if entries != 1 || freed <= 0 {
		t.Fatalf("freed %d bytes in %d entries, want one non-empty entry", freed, entries)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("the cache directory should be gone")
	}
}

func TestCleanOnMissingDirectoryIsNotAnError(t *testing.T) {
	freed, entries, err := Clean(filepath.Join(t.TempDir(), "never-created"))
	if err != nil {
		t.Fatalf("Clean: %v", err)
	}
	if freed != 0 || entries != 0 {
		t.Fatalf("freed %d bytes in %d entries, want zero", freed, entries)
	}
}
