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

// writeStale rewrites an entry with a store time past the TTL, so the next read has to
// revalidate instead of serving from the TTL window.
func writeStale(c *cache.Cache, key string, data []byte, etag string) error {
	entry := cache.Entry{
		Key:      key,
		StoredAt: time.Now().Add(-2 * cache.TTL),
		ETag:     etag,
		Data:     data,
	}
	encoded, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	return os.WriteFile(c.Path(cache.BucketRegistry, key), encoded, 0o644)
}
