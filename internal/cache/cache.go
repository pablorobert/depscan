// Package cache is depscan's on-disk HTTP cache.
//
// It lives in os.UserCacheDir()/depscan and never touches the scanned project.
// Entries carry both a store timestamp (for TTL) and an ETag (for revalidation);
// the two are complementary, not alternatives. SPEC.md section 13.1.
package cache

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// TTL is how long an entry is served without revalidation.
const TTL = 6 * time.Hour

// Buckets.
const (
	BucketRegistry   = "registry"
	BucketAdvisories = "advisories"
)

// Entry is one cached response.
type Entry struct {
	// Key is the logical key, stored for debuggability since filenames are hashed.
	Key      string    `json:"key"`
	StoredAt time.Time `json:"storedAt"`
	ETag     string    `json:"etag"`
	// Data is gzipped on disk and inflated by Get, so callers always see the plain
	// payload. Packuments compress about five to eight times.
	Data []byte `json:"data"`
}

// Fresh reports whether the entry is within the TTL.
func (e *Entry) Fresh() bool {
	return time.Since(e.StoredAt) < TTL
}

// Cache is a filesystem-backed cache. A disabled cache satisfies every call without
// touching disk, so callers need no conditionals.
type Cache struct {
	dir     string
	enabled bool
}

// New returns a cache rooted at os.UserCacheDir()/depscan. If the directory cannot be
// determined or created, a disabled cache is returned together with the error, so the
// scan can proceed without caching.
func New(enabled bool) (*Cache, error) {
	if !enabled {
		return &Cache{enabled: false}, nil
	}
	base, err := os.UserCacheDir()
	if err != nil {
		return &Cache{enabled: false}, err
	}
	return NewAt(filepath.Join(base, "depscan"))
}

// NewAt returns a cache rooted at an explicit directory.
func NewAt(dir string) (*Cache, error) {
	for _, b := range []string{BucketRegistry, BucketAdvisories} {
		if err := os.MkdirAll(filepath.Join(dir, b), 0o755); err != nil {
			return &Cache{enabled: false}, err
		}
	}
	return &Cache{dir: dir, enabled: true}, nil
}

// Dir returns the cache directory, empty when disabled.
func (c *Cache) Dir() string {
	if !c.enabled {
		return ""
	}
	return c.dir
}

// Enabled reports whether the cache is active.
func (c *Cache) Enabled() bool { return c.enabled }

// path hashes the key so any package name — scoped, with slashes, arbitrarily long —
// maps to a safe filename and cannot escape the bucket.
func (c *Cache) path(bucket, key string) string {
	sum := sha256.Sum256([]byte(key))
	return filepath.Join(c.dir, bucket, hex.EncodeToString(sum[:])+".json")
}

// Path returns the file backing one entry. Useful for diagnostics and for tests that
// need to age an entry past the TTL.
func (c *Cache) Path(bucket, key string) string {
	if !c.enabled {
		return ""
	}
	return c.path(bucket, key)
}

// Get returns the cached entry for key. A missing, unreadable or corrupt entry is
// reported as a miss; a corrupt file is removed so it cannot poison later runs.
// A stale entry is still returned so its ETag can be used to revalidate.
func (c *Cache) Get(bucket, key string) (*Entry, bool) {
	if !c.enabled {
		return nil, false
	}
	p := c.path(bucket, key)
	raw, err := os.ReadFile(p)
	if err != nil {
		return nil, false
	}
	var e Entry
	if err := json.Unmarshal(raw, &e); err != nil || len(e.Data) == 0 {
		_ = os.Remove(p)
		return nil, false
	}

	data, err := decompress(e.Data)
	if err != nil {
		// A payload that will not inflate is unusable. This also covers an entry left
		// by a depscan that stored payloads uncompressed: it is dropped and refetched.
		_ = os.Remove(p)
		return nil, false
	}
	e.Data = data
	return &e, true
}

// DefaultDir returns the canonical cache location without creating it, so the
// inspection and removal commands work even when caching is switched off for the run.
func DefaultDir() (string, error) {
	base, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "depscan"), nil
}

// BucketStats summarizes one bucket.
type BucketStats struct {
	Name    string
	Entries int
	Bytes   int64
}

// LargestEntry is one of the heaviest entries, named by the key it was stored under so
// a reader sees the package rather than a hash.
type LargestEntry struct {
	Key   string
	Bytes int64
}

// Stats describes what the cache currently holds.
type Stats struct {
	Dir        string
	Exists     bool
	Entries    int
	Bytes      int64
	Buckets    []BucketStats
	Largest    []LargestEntry
	Unreadable int
}

// Inspect walks the cache and reports its size, per bucket, plus the heaviest entries.
//
// Only the largest few entries are opened: sizes come from the directory walk, and the
// key is read afterwards just for the ones that will actually be shown.
func Inspect(dir string, topN int) (*Stats, error) {
	st := &Stats{Dir: dir}

	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		return st, nil
	}
	st.Exists = true

	type sized struct {
		path  string
		bytes int64
	}
	var all []sized
	perBucket := map[string]*BucketStats{}

	err = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			st.Unreadable++
			return nil
		}
		if d.IsDir() {
			return nil
		}
		fi, statErr := d.Info()
		if statErr != nil {
			st.Unreadable++
			return nil
		}
		size := fi.Size()
		st.Entries++
		st.Bytes += size

		bucket := "other"
		if rel, relErr := filepath.Rel(dir, path); relErr == nil {
			bucket = filepath.ToSlash(filepath.Dir(rel))
		}
		b, ok := perBucket[bucket]
		if !ok {
			b = &BucketStats{Name: bucket}
			perBucket[bucket] = b
		}
		b.Entries++
		b.Bytes += size

		all = append(all, sized{path: path, bytes: size})
		return nil
	})
	if err != nil {
		return st, err
	}

	for _, b := range perBucket {
		st.Buckets = append(st.Buckets, *b)
	}
	sort.Slice(st.Buckets, func(i, j int) bool { return st.Buckets[i].Bytes > st.Buckets[j].Bytes })

	sort.Slice(all, func(i, j int) bool { return all[i].bytes > all[j].bytes })
	if topN > len(all) {
		topN = len(all)
	}
	for _, s := range all[:topN] {
		st.Largest = append(st.Largest, LargestEntry{Key: keyOf(s.path), Bytes: s.bytes})
	}
	return st, nil
}

// keyOf reads just the key out of an entry file, falling back to the filename when the
// entry cannot be read.
func keyOf(path string) string {
	raw, err := os.ReadFile(path)
	if err != nil {
		return filepath.Base(path)
	}
	var e struct {
		Key string `json:"key"`
	}
	if err := json.Unmarshal(raw, &e); err != nil || e.Key == "" {
		return filepath.Base(path)
	}
	return e.Key
}

// Clean removes the cache directory and reports what it freed. Removing the cache is
// always safe: every entry is a copy of something the registry can serve again.
func Clean(dir string) (freedBytes int64, freedEntries int, err error) {
	st, err := Inspect(dir, 0)
	if err != nil {
		return 0, 0, err
	}
	if !st.Exists {
		return 0, 0, nil
	}
	if err := os.RemoveAll(dir); err != nil {
		return 0, 0, err
	}
	return st.Bytes, st.Entries, nil
}

func compress(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	zw, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return nil, err
	}
	if _, err := zw.Write(data); err != nil {
		zw.Close()
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func decompress(data []byte) ([]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	return io.ReadAll(zr)
}

// Put stores data under key. The write goes to a temporary file in the same directory
// and is then renamed, so a reader never observes a partial entry and concurrent
// depscan runs cannot corrupt each other. A failure to cache is not a scan failure.
func (c *Cache) Put(bucket, key string, data []byte, etag string) error {
	if !c.enabled {
		return nil
	}
	// Compressing before the envelope matters twice over: the payload itself shrinks
	// five to eight times, and the base64 the JSON envelope applies then runs over the
	// smaller bytes instead of inflating the raw document by a third.
	packed, err := compress(data)
	if err != nil {
		return err
	}
	e := Entry{Key: key, StoredAt: time.Now(), ETag: etag, Data: packed}
	encoded, err := json.Marshal(e)
	if err != nil {
		return err
	}

	final := c.path(bucket, key)
	tmp, err := os.CreateTemp(filepath.Dir(final), ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		// Harmless when the rename already consumed the file.
		_ = os.Remove(tmpName)
	}()

	if _, err := tmp.Write(encoded); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return replace(tmpName, final)
}

// replace renames tmp over final, retrying briefly. On Windows the rename fails while
// another process still holds the destination open, which happens routinely when
// several depscan runs share a cache, and it clears within milliseconds.
func replace(tmpName, final string) error {
	var err error
	for attempt := range 5 {
		if err = os.Rename(tmpName, final); err == nil {
			return nil
		}
		time.Sleep(time.Duration(attempt+1) * 2 * time.Millisecond)
	}
	return err
}
