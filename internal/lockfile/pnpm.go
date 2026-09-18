package lockfile

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// pnpmLock covers pnpm-lock.yaml 6.0 and 9.0. The packages map is the resolved set;
// the importer sections say which version the project itself resolved each declared
// dependency to, which is what separates the direct copy from nested ones.
type pnpmLock struct {
	LockfileVersion yaml.Node            `yaml:"lockfileVersion"`
	Packages        map[string]yaml.Node `yaml:"packages"`
	Snapshots       map[string]yaml.Node `yaml:"snapshots"`
	// 9.0 (and workspaces in 6.0) nest the sections under importers; the project's own
	// importer is ".".
	Importers map[string]pnpmImporter `yaml:"importers"`
	// A single-project 6.0 lockfile puts the same sections at the root.
	pnpmImporter `yaml:",inline"`
}

// pnpmImporter holds one importer's resolved direct dependencies. Each value is
// either {specifier, version} (6.0, 9.0) or a bare version string (5.x).
type pnpmImporter struct {
	Dependencies         map[string]yaml.Node `yaml:"dependencies"`
	DevDependencies      map[string]yaml.Node `yaml:"devDependencies"`
	OptionalDependencies map[string]yaml.Node `yaml:"optionalDependencies"`
}

// topLevel returns the name@version pairs the importer resolved, peer annotations
// stripped.
func (imp pnpmImporter) topLevel() map[string]bool {
	out := make(map[string]bool)
	for _, section := range []map[string]yaml.Node{
		imp.Dependencies, imp.DevDependencies, imp.OptionalDependencies,
	} {
		for name, node := range section {
			version := node.Value
			if node.Kind == yaml.MappingNode {
				var v struct {
					Version string `yaml:"version"`
				}
				if err := node.Decode(&v); err != nil {
					continue
				}
				version = v.Version
			}
			// 5.x appends peers with '_' rather than parentheses.
			version, _, _ = strings.Cut(stripPeerSuffix(version), "_")
			if version != "" {
				out[name+"@"+version] = true
			}
		}
	}
	return out
}

// parsePNPM reads pnpm-lock.yaml. Keys differ between lockfile generations:
//
//	9.0: "@esbuild/aix-ppc64@0.21.5"
//	6.0: "/@esbuild/aix-ppc64/0.21.5" or "/lodash/4.17.21"
//
// Versions may carry a peer-dependency annotation, "5.4.21(@types/node@20.0.0)",
// which is stripped.
func parsePNPM(path string) ([]resolvedEntry, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var lock pnpmLock
	if err := yaml.Unmarshal(raw, &lock); err != nil {
		return nil, fmt.Errorf("pnpm-lock.yaml: %w", err)
	}

	keys := make([]string, 0, len(lock.Packages)+len(lock.Snapshots))
	for k := range lock.Packages {
		keys = append(keys, k)
	}
	if len(lock.Packages) == 0 {
		// Very old or partial lockfiles put the resolved set under snapshots only.
		for k := range lock.Snapshots {
			keys = append(keys, k)
		}
	}

	own := lock.pnpmImporter
	if imp, ok := lock.Importers["."]; ok {
		own = imp
	}
	topLevel := own.topLevel()

	entries := make([]resolvedEntry, 0, len(keys))
	for _, key := range keys {
		// The peer annotation must go before the split, not after: it contains '@'
		// itself, so "/next@14.1.2(react@18.0.0)" would otherwise split on the '@'
		// inside the parentheses and lose the package entirely.
		name, version := pnpmSplitKey(stripPeerSuffix(key))
		if name == "" || !isConcreteVersion(version) {
			continue
		}
		entries = append(entries, resolvedEntry{
			Name:     name,
			Version:  version,
			TopLevel: topLevel[name+"@"+version],
		})
	}
	return entries, nil
}

// pnpmSplitKey handles both the v9 "name@version" and the v6 "/name/version" key
// shapes, including scoped names.
func pnpmSplitKey(key string) (name, version string) {
	if key == "" {
		return "", ""
	}
	if strings.HasPrefix(key, "/") {
		trimmed := key[1:]
		// v6 with an '@' separator: "/@scope/pkg@1.0.0" or "/pkg@1.0.0".
		if i := strings.LastIndexByte(trimmed, '@'); i > 0 {
			return trimmed[:i], trimmed[i+1:]
		}
		// Older v6 with a '/' separator: "/@scope/pkg/1.0.0" or "/pkg/1.0.0".
		if i := strings.LastIndexByte(trimmed, '/'); i > 0 {
			return trimmed[:i], trimmed[i+1:]
		}
		return trimmed, ""
	}
	return splitNameVersion(key)
}
