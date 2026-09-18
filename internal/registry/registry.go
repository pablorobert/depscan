// Package registry talks to the npm registry for version information.
//
// Two endpoints are used, with very different costs (measured, see SPEC.md appendix A):
//
//	/-/package/<pkg>/dist-tags   79 bytes, no ETag and no Cache-Control
//	/<pkg> (abbreviated)         ~54 KB gzipped, has ETag + max-age=300
//
// So `latest` is always cheap and the full version list is only fetched when a caller
// actually needs `wanted`.
package registry

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/pablorobert/depscan/internal/cache"
	"github.com/pablorobert/depscan/internal/model"
)

// DefaultBaseURL is the public npm registry.
const DefaultBaseURL = "https://registry.npmjs.org"

// abbreviatedAccept asks for the install-oriented packument, which is roughly a third
// of the full document.
const abbreviatedAccept = "application/vnd.npm.install-v1+json"

// Error carries the failure kind so it can be reported on the affected project
// without the caller inspecting strings.
type Error struct {
	Kind model.ErrorKind
	Msg  string
}

func (e *Error) Error() string { return e.Msg }

func networkErr(format string, args ...any) *Error {
	return &Error{Kind: model.ErrNetwork, Msg: fmt.Sprintf(format, args...)}
}

// Options configures a client.
type Options struct {
	BaseURL     string
	Cache       *cache.Cache
	Offline     bool
	Concurrency int
	Timeout     time.Duration
}

// Client fetches version metadata, using the cache and honouring offline mode.
type Client struct {
	base        string
	http        *http.Client
	cache       *cache.Cache
	offline     bool
	concurrency int
}

// New builds a client.
func New(opts Options) *Client {
	base := opts.BaseURL
	if base == "" {
		base = DefaultBaseURL
	}
	conc := opts.Concurrency
	if conc <= 0 {
		conc = 64
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	return &Client{
		base:    strings.TrimRight(base, "/"),
		http:    &http.Client{Timeout: timeout},
		cache:   opts.Cache,
		offline: opts.Offline,
		// The registry served 167 pkg/s at 256 concurrent requests with no throttling,
		// but 64 is the polite default.
		concurrency: conc,
	}
}

// distTags is the dist-tags document: a map of tag name to version.
type distTags map[string]string

// packument is the abbreviated packument, reduced to what depscan needs.
type packument struct {
	DistTags map[string]string          `json:"dist-tags"`
	Versions map[string]json.RawMessage `json:"versions"`
}

// LatestBatch resolves the `latest` dist-tag for every name, concurrently.
// The returned maps are keyed by package name; a name appears in exactly one of them.
func (c *Client) LatestBatch(ctx context.Context, names []string) (map[string]string, map[string]error) {
	var (
		mu      sync.Mutex
		latest  = make(map[string]string, len(names))
		failure = make(map[string]error, 0)
	)

	c.each(ctx, names, func(name string) {
		v, err := c.latest(ctx, name)
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			failure[name] = err
			return
		}
		latest[name] = v
	})
	return latest, failure
}

// VersionsBatch fetches the full published version list for every name. This is the
// expensive path (measured 8.4 packages/s) and is only called for packages whose
// `latest` falls outside the declared range, under --wanted.
func (c *Client) VersionsBatch(ctx context.Context, names []string) (map[string][]string, map[string]error) {
	var (
		mu       sync.Mutex
		versions = make(map[string][]string, len(names))
		failure  = make(map[string]error)
	)

	c.each(ctx, names, func(name string) {
		vs, err := c.versions(ctx, name)
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			failure[name] = err
			return
		}
		versions[name] = vs
	})
	return versions, failure
}

// Releases maps every published version of a package to its publish time.
type Releases map[string]time.Time

// ReleasesBatch fetches publish times for every name. Only the full packument carries
// them — the abbreviated one has a single "modified" date — so this is the most
// expensive request depscan makes (measured for zod: 460 KB full against 345 KB
// abbreviated, both gzipped). It is only called for outdated packages of projects
// whose package manager enforces a minimum release age.
func (c *Client) ReleasesBatch(ctx context.Context, names []string) (map[string]Releases, map[string]error) {
	var (
		mu       sync.Mutex
		releases = make(map[string]Releases, len(names))
		failure  = make(map[string]error)
	)

	c.each(ctx, names, func(name string) {
		r, err := c.releases(ctx, name)
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			failure[name] = err
			return
		}
		releases[name] = r
	})
	return releases, failure
}

// releaseDoc is both the subset of the full packument that is decoded and the shape
// that is cached: only versions and their times are kept, so a multi-megabyte
// packument costs a few kilobytes on disk.
type releaseDoc struct {
	Versions map[string]json.RawMessage `json:"versions"`
	Time     map[string]string          `json:"time"`
}

func (c *Client) releases(ctx context.Context, name string) (Releases, error) {
	key := "releases:" + name
	entry, cached := c.cacheGet(cache.BucketRegistry, key)

	if cached && entry.Fresh() {
		if r, err := releasesFrom(entry.Data); err == nil {
			return r, nil
		}
	}

	if c.offline {
		if cached {
			if r, err := releasesFrom(entry.Data); err == nil {
				return r, nil
			}
		}
		return nil, &Error{
			Kind: model.ErrCacheMissOffline,
			Msg:  fmt.Sprintf("%s: offline and no cached publish dates", name),
		}
	}

	etag := ""
	if cached {
		etag = entry.ETag
	}

	body, newETag, err := c.get(ctx, c.base+"/"+escapeName(name), "application/json", etag)
	if err != nil {
		return nil, err
	}
	if body == nil && cached {
		c.cachePut(cache.BucketRegistry, key, entry.Data, entry.ETag)
		return releasesFrom(entry.Data)
	}

	var doc releaseDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, networkErr("%s: malformed packument response", name)
	}
	slim := releaseDoc{Versions: make(map[string]json.RawMessage, len(doc.Versions)), Time: make(map[string]string, len(doc.Versions))}
	for v := range doc.Versions {
		slim.Versions[v] = json.RawMessage("{}")
		if t, ok := doc.Time[v]; ok {
			slim.Time[v] = t
		}
	}
	data, err := json.Marshal(slim)
	if err != nil {
		return nil, &Error{Kind: model.ErrInternal, Msg: err.Error()}
	}
	c.cachePut(cache.BucketRegistry, key, data, newETag)
	return releasesFrom(data)
}

// releasesFrom keeps only versions still published and with a parseable time; the
// time map also lists unpublished versions and the "created"/"modified" keys.
func releasesFrom(data []byte) (Releases, error) {
	var doc releaseDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	out := make(Releases, len(doc.Versions))
	for v := range doc.Versions {
		t, err := time.Parse(time.RFC3339, doc.Time[v])
		if err != nil {
			continue
		}
		out[v] = t
	}
	return out, nil
}

// each runs fn over names with bounded concurrency.
func (c *Client) each(ctx context.Context, names []string, fn func(string)) {
	if len(names) == 0 {
		return
	}
	work := make(chan string)
	var wg sync.WaitGroup

	workers := min(c.concurrency, len(names))
	for range workers {
		wg.Go(func() {
			for name := range work {
				if ctx.Err() != nil {
					return
				}
				fn(name)
			}
		})
	}
	for _, n := range names {
		select {
		case work <- n:
		case <-ctx.Done():
			close(work)
			wg.Wait()
			return
		}
	}
	close(work)
	wg.Wait()
}

// latest returns the `latest` dist-tag for one package. dist-tags carries no ETag and
// no Cache-Control, so the on-disk TTL is the only revalidation mechanism available.
func (c *Client) latest(ctx context.Context, name string) (string, error) {
	key := "dist-tags:" + name

	if entry, ok := c.cacheGet(cache.BucketRegistry, key); ok && entry.Fresh() {
		if v, err := latestFrom(entry.Data); err == nil {
			return v, nil
		}
	}

	if c.offline {
		// A stale entry is better than nothing, but the caller must know it came from
		// an expired cache rather than from the registry.
		if entry, ok := c.cacheGet(cache.BucketRegistry, key); ok {
			if v, err := latestFrom(entry.Data); err == nil {
				return v, nil
			}
		}
		return "", &Error{
			Kind: model.ErrCacheMissOffline,
			Msg:  fmt.Sprintf("%s: offline and no cached dist-tags", name),
		}
	}

	body, _, err := c.get(ctx, c.base+"/-/package/"+escapeName(name)+"/dist-tags", "", "")
	if err != nil {
		return "", err
	}
	v, parseErr := latestFrom(body)
	if parseErr != nil {
		return "", networkErr("%s: malformed dist-tags response", name)
	}
	c.cachePut(cache.BucketRegistry, key, body, "")
	return v, nil
}

func latestFrom(data []byte) (string, error) {
	var tags distTags
	if err := json.Unmarshal(data, &tags); err != nil {
		return "", err
	}
	v, ok := tags["latest"]
	if !ok || v == "" {
		return "", errors.New("no latest dist-tag")
	}
	return v, nil
}

// versions returns every published version of one package, from the abbreviated
// packument. The packument does carry an ETag, so a stale cache entry is revalidated
// with If-None-Match rather than re-downloaded (measured: 304 in 183ms, zero bytes).
func (c *Client) versions(ctx context.Context, name string) ([]string, error) {
	key := "packument:" + name
	entry, cached := c.cacheGet(cache.BucketRegistry, key)

	if cached && entry.Fresh() {
		if vs, err := versionsFrom(entry.Data); err == nil {
			return vs, nil
		}
	}

	if c.offline {
		if cached {
			if vs, err := versionsFrom(entry.Data); err == nil {
				return vs, nil
			}
		}
		return nil, &Error{
			Kind: model.ErrCacheMissOffline,
			Msg:  fmt.Sprintf("%s: offline and no cached packument", name),
		}
	}

	etag := ""
	if cached {
		etag = entry.ETag
	}

	body, newETag, err := c.get(ctx, c.base+"/"+escapeName(name), abbreviatedAccept, etag)
	if err != nil {
		return nil, err
	}
	if body == nil && cached {
		// 304: the cached body is still current. Refresh its timestamp so the TTL
		// restarts without another download.
		c.cachePut(cache.BucketRegistry, key, entry.Data, entry.ETag)
		return versionsFrom(entry.Data)
	}

	vs, parseErr := versionsFrom(body)
	if parseErr != nil {
		return nil, networkErr("%s: malformed packument response", name)
	}
	c.cachePut(cache.BucketRegistry, key, body, newETag)
	return vs, nil
}

func versionsFrom(data []byte) ([]string, error) {
	var doc packument
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(doc.Versions))
	for v := range doc.Versions {
		out = append(out, v)
	}
	return out, nil
}

// get performs a GET with retries. It returns a nil body when the server answered 304,
// meaning the caller's cached copy is current.
func (c *Client) get(ctx context.Context, rawURL, accept, etag string) ([]byte, string, error) {
	const attempts = 3
	var lastErr error

	for attempt := range attempts {
		if attempt > 0 {
			delay := time.Duration(1<<uint(attempt-1)) * 300 * time.Millisecond
			select {
			case <-time.After(delay):
			case <-ctx.Done():
				return nil, "", networkErr("%s: %v", rawURL, ctx.Err())
			}
		}

		body, newETag, retryable, err := c.attempt(ctx, rawURL, accept, etag)
		if err == nil {
			return body, newETag, nil
		}
		lastErr = err
		if !retryable {
			break
		}
	}
	return nil, "", lastErr
}

// attempt performs a single request. The boolean reports whether a retry is worthwhile.
func (c *Client) attempt(ctx context.Context, rawURL, accept, etag string) (body []byte, newETag string, retryable bool, err error) {
	u, parseErr := url.Parse(rawURL)
	if parseErr != nil {
		return nil, "", false, &Error{Kind: model.ErrInternal, Msg: fmt.Sprintf("bad url %q: %v", rawURL, parseErr)}
	}

	req, reqErr := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if reqErr != nil {
		return nil, "", false, &Error{Kind: model.ErrInternal, Msg: reqErr.Error()}
	}
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	req.Header.Set("User-Agent", "depscan")

	resp, doErr := c.http.Do(req)
	if doErr != nil {
		kind := model.ErrNetwork
		if errors.Is(doErr, context.DeadlineExceeded) || isTimeout(doErr) {
			kind = model.ErrTimeout
		}
		return nil, "", true, &Error{Kind: kind, Msg: fmt.Sprintf("%s: %v", rawURL, doErr)}
	}
	defer resp.Body.Close()

	switch {
	case resp.StatusCode == http.StatusNotModified:
		return nil, resp.Header.Get("ETag"), false, nil
	case resp.StatusCode == http.StatusOK:
		data, readErr := readBody(resp)
		if readErr != nil {
			return nil, "", true, networkErr("%s: %v", rawURL, readErr)
		}
		return data, resp.Header.Get("ETag"), false, nil
	case resp.StatusCode == http.StatusNotFound:
		return nil, "", false, networkErr("%s: not found in registry", rawURL)
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		// The public registry answers 401 for a scoped package it will not disclose,
		// so this covers both a private package and a name that does not exist.
		return nil, "", false, networkErr(
			"%s: registry returned %d — the package is private or does not exist",
			rawURL, resp.StatusCode)
	case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
		return nil, "", true, networkErr("%s: registry returned %d", rawURL, resp.StatusCode)
	default:
		return nil, "", false, networkErr("%s: registry returned %d", rawURL, resp.StatusCode)
	}
}

// readBody reads a response, decompressing when the server ignored the transport's
// transparent gzip handling and set the header itself.
func readBody(resp *http.Response) ([]byte, error) {
	var r io.Reader = resp.Body
	if strings.EqualFold(resp.Header.Get("Content-Encoding"), "gzip") {
		zr, err := gzip.NewReader(resp.Body)
		if err != nil {
			return nil, err
		}
		defer zr.Close()
		r = zr
	}
	return io.ReadAll(r)
}

func isTimeout(err error) bool {
	var te interface{ Timeout() bool }
	return errors.As(err, &te) && te.Timeout()
}

// escapeName percent-encodes a package name for use in a single URL path segment, so
// that a scoped name such as "@scope/pkg" becomes "@scope%2Fpkg". Verified against the
// live registry, including 68 scoped packages in one run.
func escapeName(name string) string {
	return strings.ReplaceAll(url.PathEscape(name), "/", "%2F")
}

func (c *Client) cacheGet(bucket, key string) (*cache.Entry, bool) {
	if c.cache == nil {
		return nil, false
	}
	return c.cache.Get(bucket, key)
}

func (c *Client) cachePut(bucket, key string, data []byte, etag string) {
	if c.cache == nil {
		return
	}
	// A cache write failure must never fail the scan.
	_ = c.cache.Put(bucket, key, data, etag)
}
