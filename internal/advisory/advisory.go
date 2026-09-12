// Package advisory queries the npm bulk advisory endpoint.
//
// One POST carries every (package, version) pair in the scan. Measured: 1708 packages
// in a single request, 56 KB of payload, 400ms, unauthenticated, with version
// filtering performed server-side. SPEC.md appendix A.
package advisory

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/pablorobert/depscan/internal/cache"
	"github.com/pablorobert/depscan/internal/model"
)

// DefaultBaseURL is the public npm registry.
const DefaultBaseURL = "https://registry.npmjs.org"

const bulkPath = "/-/npm/v1/security/advisories/bulk"

// chunkSize bounds a single request. No server limit was observed at 1708 packages,
// so this is defensive rather than required.
const chunkSize = 1000

// Error carries the failure kind for reporting on affected projects.
type Error struct {
	Kind model.ErrorKind
	Msg  string
}

func (e *Error) Error() string { return e.Msg }

// wireAdvisory is the endpoint's representation, which uses snake_case and is kept
// out of the core model.
type wireAdvisory struct {
	ID                 int      `json:"id"`
	URL                string   `json:"url"`
	Title              string   `json:"title"`
	Severity           string   `json:"severity"`
	VulnerableVersions string   `json:"vulnerable_versions"`
	CWE                []string `json:"cwe"`
	CVSS               struct {
		Score        float64 `json:"score"`
		VectorString *string `json:"vectorString"`
	} `json:"cvss"`
}

// Options configures a client.
type Options struct {
	BaseURL string
	Cache   *cache.Cache
	Offline bool
	Timeout time.Duration
}

// Client queries the bulk advisory endpoint.
type Client struct {
	base    string
	http    *http.Client
	cache   *cache.Cache
	offline bool
}

// New builds a client.
func New(opts Options) *Client {
	base := opts.BaseURL
	if base == "" {
		base = DefaultBaseURL
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
	}
}

// Query asks the endpoint about every package version in req, which maps a package
// name to the versions in use across the whole scan. The result maps a package name to
// the advisories affecting those versions; packages with no advisory are absent, which
// is how the endpoint answers.
func (c *Client) Query(ctx context.Context, req map[string][]string) (map[string][]model.Advisory, error) {
	if len(req) == 0 {
		return map[string][]model.Advisory{}, nil
	}

	out := make(map[string][]model.Advisory)
	for _, chunk := range chunks(req) {
		part, err := c.queryChunk(ctx, chunk)
		if err != nil {
			return nil, err
		}
		for name, advs := range part {
			out[name] = append(out[name], advs...)
		}
	}
	return out, nil
}

// chunks splits the request deterministically, by sorted package name, so the cache
// key of each chunk is stable across runs.
func chunks(req map[string][]string) []map[string][]string {
	names := make([]string, 0, len(req))
	for n := range req {
		names = append(names, n)
	}
	sort.Strings(names)

	var out []map[string][]string
	for i := 0; i < len(names); i += chunkSize {
		end := min(i+chunkSize, len(names))
		part := make(map[string][]string, end-i)
		for _, n := range names[i:end] {
			versions := append([]string(nil), req[n]...)
			sort.Strings(versions)
			part[n] = versions
		}
		out = append(out, part)
	}
	return out
}

func (c *Client) queryChunk(ctx context.Context, chunk map[string][]string) (map[string][]model.Advisory, error) {
	payload, err := json.Marshal(chunk)
	if err != nil {
		return nil, &Error{Kind: model.ErrInternal, Msg: err.Error()}
	}
	key := "bulk:" + hash(payload)

	if entry, ok := c.cacheGet(key); ok && entry.Fresh() {
		if res, err := decode(entry.Data); err == nil {
			return res, nil
		}
	}

	if c.offline {
		if entry, ok := c.cacheGet(key); ok {
			if res, err := decode(entry.Data); err == nil {
				return res, nil
			}
		}
		return nil, &Error{
			Kind: model.ErrCacheMissOffline,
			Msg:  "offline and no cached advisory data for this dependency set",
		}
	}

	body, err := c.post(ctx, payload)
	if err != nil {
		return nil, err
	}
	res, decodeErr := decode(body)
	if decodeErr != nil {
		return nil, &Error{Kind: model.ErrNetwork, Msg: "malformed advisory response"}
	}
	c.cachePut(key, body)
	return res, nil
}

// post sends one bulk request, retrying transient failures.
func (c *Client) post(ctx context.Context, payload []byte) ([]byte, error) {
	const attempts = 3
	var lastErr error

	for attempt := range attempts {
		if attempt > 0 {
			delay := time.Duration(1<<uint(attempt-1)) * 300 * time.Millisecond
			select {
			case <-time.After(delay):
			case <-ctx.Done():
				return nil, &Error{Kind: model.ErrNetwork, Msg: ctx.Err().Error()}
			}
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost,
			c.base+bulkPath, bytes.NewReader(payload))
		if err != nil {
			return nil, &Error{Kind: model.ErrInternal, Msg: err.Error()}
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "depscan")

		resp, doErr := c.http.Do(req)
		if doErr != nil {
			kind := model.ErrNetwork
			if errors.Is(doErr, context.DeadlineExceeded) || isTimeout(doErr) {
				kind = model.ErrTimeout
			}
			lastErr = &Error{Kind: kind, Msg: fmt.Sprintf("advisory request failed: %v", doErr)}
			continue
		}

		data, readErr := readAll(resp)
		resp.Body.Close()

		switch {
		case resp.StatusCode == http.StatusOK && readErr == nil:
			return data, nil
		case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
			lastErr = &Error{
				Kind: model.ErrNetwork,
				Msg:  fmt.Sprintf("advisory endpoint returned %d", resp.StatusCode),
			}
		case readErr != nil:
			lastErr = &Error{Kind: model.ErrNetwork, Msg: readErr.Error()}
		default:
			return nil, &Error{
				Kind: model.ErrNetwork,
				Msg:  fmt.Sprintf("advisory endpoint returned %d", resp.StatusCode),
			}
		}
	}
	if lastErr == nil {
		lastErr = &Error{Kind: model.ErrNetwork, Msg: "advisory request failed"}
	}
	return nil, fmt.Errorf("%w after %d attempts", lastErr, attempts)
}

// decode converts the wire representation into the core model, normalizing severity.
func decode(body []byte) (map[string][]model.Advisory, error) {
	var wire map[string][]wireAdvisory
	if err := json.Unmarshal(body, &wire); err != nil {
		return nil, err
	}
	out := make(map[string][]model.Advisory, len(wire))
	for name, list := range wire {
		advs := make([]model.Advisory, 0, len(list))
		for _, w := range list {
			advs = append(advs, model.Advisory{
				ID:                 w.ID,
				URL:                w.URL,
				Title:              w.Title,
				Severity:           model.ParseSeverity(w.Severity),
				VulnerableVersions: w.VulnerableVersions,
				CWE:                w.CWE,
				CVSS: model.CVSS{
					Score:        w.CVSS.Score,
					VectorString: w.CVSS.VectorString,
				},
			})
		}
		sort.Slice(advs, func(i, j int) bool { return advs[i].ID < advs[j].ID })
		out[name] = advs
	}
	return out, nil
}

func readAll(resp *http.Response) ([]byte, error) {
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(resp.Body); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func hash(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func isTimeout(err error) bool {
	var te interface{ Timeout() bool }
	return errors.As(err, &te) && te.Timeout()
}

func (c *Client) cacheGet(key string) (*cache.Entry, bool) {
	if c.cache == nil {
		return nil, false
	}
	return c.cache.Get(cache.BucketAdvisories, key)
}

func (c *Client) cachePut(key string, data []byte) {
	if c.cache == nil {
		return
	}
	_ = c.cache.Put(cache.BucketAdvisories, key, data, "")
}
