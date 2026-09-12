package lockfile

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// npmLock covers package-lock.json v1 (dependencies) as well as v2 and v3 (packages).
// v2 carries both; the packages map is preferred because it is flat and unambiguous.
type npmLock struct {
	LockfileVersion int                        `json:"lockfileVersion"`
	Packages        map[string]npmPackage      `json:"packages"`
	Dependencies    map[string]npmV1Dependency `json:"dependencies"`
}

type npmPackage struct {
	Version string `json:"version"`
	Link    bool   `json:"link"`
}

type npmV1Dependency struct {
	Version      string                     `json:"version"`
	Dependencies map[string]npmV1Dependency `json:"dependencies"`
}

// parseNPM reads package-lock.json. Nested node_modules paths are kept as separate
// entries, so the same package appearing at two versions is reported twice rather
// than collapsed.
func parseNPM(path string) ([]resolvedEntry, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var lock npmLock
	if err := json.Unmarshal(raw, &lock); err != nil {
		return nil, fmt.Errorf("package-lock.json: %w", err)
	}

	if len(lock.Packages) > 0 {
		entries := make([]resolvedEntry, 0, len(lock.Packages))
		for key, pkg := range lock.Packages {
			if key == "" || pkg.Link {
				// "" is the project itself; a link is a workspace alias.
				continue
			}
			name := npmNameFromPath(key)
			if name == "" || !isConcreteVersion(pkg.Version) {
				continue
			}
			entries = append(entries, resolvedEntry{Name: name, Version: pkg.Version})
		}
		return entries, nil
	}

	if len(lock.Dependencies) > 0 {
		var entries []resolvedEntry
		collectNPMv1(lock.Dependencies, &entries)
		return entries, nil
	}

	if lock.LockfileVersion == 0 {
		return nil, fmt.Errorf("package-lock.json: no lockfileVersion and no dependency data")
	}
	// A lockfile for a project with no dependencies is legitimately empty.
	return nil, nil
}

// npmNameFromPath turns a lockfile key such as "node_modules/a/node_modules/@s/b"
// into the package name "@s/b".
func npmNameFromPath(key string) string {
	const marker = "node_modules/"
	i := strings.LastIndex(key, marker)
	if i < 0 {
		return ""
	}
	return key[i+len(marker):]
}

// collectNPMv1 walks the recursive dependency tree used by lockfileVersion 1.
func collectNPMv1(deps map[string]npmV1Dependency, out *[]resolvedEntry) {
	for name, dep := range deps {
		if isConcreteVersion(dep.Version) {
			*out = append(*out, resolvedEntry{Name: name, Version: dep.Version})
		}
		if len(dep.Dependencies) > 0 {
			collectNPMv1(dep.Dependencies, out)
		}
	}
}
