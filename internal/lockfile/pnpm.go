package lockfile

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// pnpmLock covers pnpm-lock.yaml 6.0 and 9.0. Only the packages map is needed for the
// resolved set; importers carry the declared ranges, which depscan already has from
// package.json.
type pnpmLock struct {
	LockfileVersion yaml.Node            `yaml:"lockfileVersion"`
	Packages        map[string]yaml.Node `yaml:"packages"`
	Snapshots       map[string]yaml.Node `yaml:"snapshots"`
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

	entries := make([]resolvedEntry, 0, len(keys))
	for _, key := range keys {
		name, version := pnpmSplitKey(key)
		version = stripPeerSuffix(version)
		if name == "" || !isConcreteVersion(version) {
			continue
		}
		entries = append(entries, resolvedEntry{Name: name, Version: version})
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
