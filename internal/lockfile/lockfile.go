// Package lockfile turns a project's lockfile into a resolved dependency set.
//
// The lockfile is the source of truth for "which version is actually in use".
// node_modules is never read. SPEC.md section 7.
package lockfile

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/pablorobert/depscan/internal/model"
)

// Kind identifies a lockfile flavour.
type Kind string

const (
	KindBunText Kind = "bun.lock"
	KindBunBin  Kind = "bun.lockb"
	KindNPM     Kind = "package-lock.json"
	KindPNPM    Kind = "pnpm-lock.yaml"
	KindYarn    Kind = "yarn.lock"
	KindNone    Kind = ""
)

// Manager returns the package manager a lockfile kind implies.
func (k Kind) Manager() string {
	switch k {
	case KindBunText, KindBunBin:
		return "bun"
	case KindNPM:
		return "npm"
	case KindPNPM:
		return "pnpm"
	case KindYarn:
		return "yarn"
	default:
		return "unknown"
	}
}

// ErrNoLockfile is returned when a project has no recognizable lockfile. The caller
// must not guess an installed version from the declared ranges.
var ErrNoLockfile = errors.New("no lockfile found")

// Declared is one entry of a project's package.json dependency sections.
type Declared struct {
	Range    string
	Category model.Category
}

// Result is the outcome of parsing one lockfile.
type Result struct {
	Kind Kind
	Deps []model.Dep
}

// detectionOrder is the priority used when several lockfiles coexist in one directory,
// which happens when a project migrated between package managers and left the old file
// behind. Bun first, npm last, because a stale package-lock.json is the most common
// leftover.
var detectionOrder = []Kind{KindBunText, KindBunBin, KindPNPM, KindYarn, KindNPM}

// Detect returns the lockfile kind present in dir, or KindNone.
func Detect(dir string) Kind {
	for _, k := range detectionOrder {
		if st, err := os.Stat(filepath.Join(dir, string(k))); err == nil && !st.IsDir() {
			return k
		}
	}
	return KindNone
}

// ParseOptions controls optional behaviour of the parsers.
type ParseOptions struct {
	// AllowBunSpawn permits the single `bun pm ls --all` invocation that is the only
	// way to read a binary bun.lockb. Encapsulated here so the rest of depscan stays
	// free of package-manager dependencies. SPEC.md section 7.2.
	AllowBunSpawn bool
	// SpawnTimeoutSeconds bounds that invocation.
	SpawnTimeoutSeconds int
}

// Parse reads the lockfile in dir and resolves it against the project's declared
// dependencies. declared marks which entries are direct and gives their category.
func Parse(dir string, declared map[string]Declared, opts ParseOptions) (*Result, error) {
	kind := Detect(dir)
	if kind == KindNone {
		return nil, ErrNoLockfile
	}

	path := filepath.Join(dir, string(kind))
	var (
		resolved []resolvedEntry
		err      error
	)

	switch kind {
	case KindBunText:
		resolved, err = parseBunText(path)
	case KindBunBin:
		resolved, err = parseBunBinary(dir, opts)
	case KindNPM:
		resolved, err = parseNPM(path)
	case KindPNPM:
		resolved, err = parsePNPM(path)
	case KindYarn:
		resolved, err = parseYarn(path)
	default:
		return nil, fmt.Errorf("unhandled lockfile kind %q", kind)
	}
	if err != nil {
		return nil, err
	}

	return &Result{Kind: kind, Deps: merge(resolved, declared)}, nil
}

// resolvedEntry is one name/version pair as found in a lockfile, before it is matched
// against the project's declared dependencies.
type resolvedEntry struct {
	Name    string
	Version string
}

// merge joins the lockfile's resolved entries with the declared ranges, marking direct
// dependencies and their category. A declared dependency missing from the lockfile is
// still reported, with an empty resolved version, so it is never silently dropped.
func merge(resolved []resolvedEntry, declared map[string]Declared) []model.Dep {
	seen := make(map[string]bool, len(resolved))
	deps := make([]model.Dep, 0, len(resolved))

	for _, r := range resolved {
		if r.Name == "" || r.Version == "" {
			continue
		}
		key := r.Name + "@" + r.Version
		if seen[key] {
			continue
		}
		seen[key] = true

		d := model.Dep{Name: r.Name, Version: r.Version}
		if dec, ok := declared[r.Name]; ok {
			d.Direct = true
			d.Declared = dec.Range
			d.Category = dec.Category
		}
		deps = append(deps, d)
	}

	// A declared dependency with no lockfile entry: keep it visible with no version.
	haveName := make(map[string]bool, len(deps))
	for _, d := range deps {
		haveName[d.Name] = true
	}
	for name, dec := range declared {
		if !haveName[name] {
			deps = append(deps, model.Dep{
				Name:     name,
				Declared: dec.Range,
				Direct:   true,
				Category: dec.Category,
			})
		}
	}

	sort.Slice(deps, func(i, j int) bool {
		if deps[i].Name != deps[j].Name {
			return deps[i].Name < deps[j].Name
		}
		return deps[i].Version < deps[j].Version
	})
	return deps
}

// splitNameVersion splits an "name@version" identifier, tolerating scoped names such
// as "@scope/pkg@1.2.3" by searching for the last '@' that is not at position zero.
func splitNameVersion(s string) (name, version string) {
	if s == "" {
		return "", ""
	}
	idx := strings.LastIndex(s, "@")
	if idx <= 0 {
		return s, ""
	}
	return s[:idx], s[idx+1:]
}

// stripPeerSuffix removes the peer-dependency annotation pnpm appends to a version,
// e.g. "5.4.21(@types/node@20.0.0)" -> "5.4.21". Measured on pnpm-lock.yaml 9.0.
func stripPeerSuffix(v string) string {
	if before, _, ok := strings.Cut(v, "("); ok {
		return strings.TrimSpace(before)
	}
	return v
}

// isConcreteVersion reports whether v looks like a resolved registry version rather
// than a link, workspace alias or git reference. Those cannot be compared against the
// registry and must not be reported as outdated.
func isConcreteVersion(v string) bool {
	if v == "" {
		return false
	}
	for _, prefix := range []string{
		"workspace:", "link:", "file:", "portal:", "git:", "git+", "npm:",
		"http:", "https:", "patch:",
	} {
		if strings.HasPrefix(v, prefix) {
			return false
		}
	}
	// A resolved version starts with a digit.
	return v[0] >= '0' && v[0] <= '9'
}
