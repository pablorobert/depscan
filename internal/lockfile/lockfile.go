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
	// TopLevel marks the copy the project itself resolved to, as opposed to a copy
	// nested under another package ("react-doctor/oxlint" in bun.lock,
	// "node_modules/a/node_modules/b" in package-lock.json). Only a top-level copy can
	// be the direct dependency.
	TopLevel bool
	// Ranges lists the requested ranges this entry satisfies, for lockfiles keyed by
	// descriptor (yarn) rather than by install location. A declared range found here
	// identifies the direct copy the same way TopLevel does.
	Ranges []string
}

// merge joins the lockfile's resolved entries with the declared ranges, marking direct
// dependencies and their category. A declared dependency missing from the lockfile is
// still reported, with an empty resolved version, so it is never silently dropped.
//
// Direct is decided per entry, not per name: a project that declares zod ^4 while a
// tool pulls in zod 3 nested has one direct zod and one transitive zod. Matching by
// name alone would report the nested copy as an outdated direct dependency.
func merge(resolved []resolvedEntry, declared map[string]Declared) []model.Dep {
	index := make(map[string]int, len(resolved))
	entries := make([]resolvedEntry, 0, len(resolved))

	for _, r := range resolved {
		if r.Name == "" || r.Version == "" {
			continue
		}
		// The same name@version can appear both hoisted and nested; it is one package
		// version, top-level if any of its copies is.
		key := r.Name + "@" + r.Version
		if i, ok := index[key]; ok {
			entries[i].TopLevel = entries[i].TopLevel || r.TopLevel
			entries[i].Ranges = append(entries[i].Ranges, r.Ranges...)
			continue
		}
		index[key] = len(entries)
		entries = append(entries, r)
	}

	byName := make(map[string][]int, len(entries))
	for i, e := range entries {
		byName[e.Name] = append(byName[e.Name], i)
	}

	direct := make([]bool, len(entries))
	for name, dec := range declared {
		candidates := byName[name]
		matched := false
		for _, i := range candidates {
			if entries[i].TopLevel || satisfiesDescriptor(entries[i].Ranges, dec.Range) {
				direct[i] = true
				matched = true
			}
		}
		if !matched {
			// The lockfile did not say which copy is the project's own (an old format,
			// or a range written differently from the descriptor). Marking every copy
			// direct can over-report, but never hides the declared dependency.
			for _, i := range candidates {
				direct[i] = true
			}
		}
	}

	deps := make([]model.Dep, 0, len(entries))
	for i, e := range entries {
		d := model.Dep{Name: e.Name, Version: e.Version}
		if direct[i] {
			dec := declared[e.Name]
			d.Direct = true
			d.Declared = dec.Range
			d.Category = dec.Category
		}
		deps = append(deps, d)
	}

	// A declared dependency with no lockfile entry: keep it visible with no version.
	for name, dec := range declared {
		if len(byName[name]) == 0 {
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

// satisfiesDescriptor reports whether a declared range is one of the ranges a
// descriptor-keyed entry was resolved for. Yarn berry prefixes registry ranges with
// "npm:", which package.json does not.
func satisfiesDescriptor(ranges []string, declared string) bool {
	for _, r := range ranges {
		if r == declared || strings.TrimPrefix(r, "npm:") == declared {
			return true
		}
	}
	return false
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
