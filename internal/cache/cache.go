// Package cache is depscan's on-disk HTTP cache.
//
// It lives in os.UserCacheDir()/depscan and never touches the scanned project.
// Entries carry both a store timestamp (for TTL) and an ETag (for revalidation);
// the two are complementary, not alternatives. SPEC.md section 13.1.
package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
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
	Data     []byte    `json:"data"`
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
	return &e, true
}

// Put stores data under key. The write goes to a temporary file in the same directory
// and is then renamed, so a reader never observes a partial entry and concurrent
// depscan runs cannot corrupt each other. A failure to cache is not a scan failure.
func (c *Cache) Put(bucket, key string, data []byte, etag string) error {
	if !c.enabled {
		return nil
	}
	e := Entry{Key: key, StoredAt: time.Now(), ETag: etag, Data: data}
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
