package registry

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/pablorobert/depscan/internal/cache"
)

// testCache builds a cache in a temporary directory so no test touches the real user
// cache.
func testCache(t *testing.T) *cache.Cache {
	t.Helper()
	c, err := cache.NewAt(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// ageEntry pushes an existing entry's store time past the TTL, so the next read has to
// revalidate instead of serving from the TTL window.
//
// It patches the file the cache itself wrote rather than composing one, so the payload
// keeps whatever on-disk encoding the cache uses.
func ageEntry(c *cache.Cache, key string) error {
	path := c.Path(cache.BucketRegistry, key)
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	var entry cache.Entry
	if err := json.Unmarshal(raw, &entry); err != nil {
		return err
	}
	entry.StoredAt = time.Now().Add(-2 * cache.TTL)

	encoded, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	return os.WriteFile(path, encoded, 0o644)
}
