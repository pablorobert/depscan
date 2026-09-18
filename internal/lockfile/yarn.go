package lockfile

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// parseYarn dispatches between the two incompatible yarn.lock formats: the custom
// text format of Yarn 1 and the YAML of Yarn 2+ (berry), which is identified by its
// __metadata block.
func parseYarn(path string) ([]resolvedEntry, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if bytes.Contains(raw, []byte("__metadata:")) {
		return parseYarnBerry(raw)
	}
	return parseYarnV1(raw), nil
}

// yarnBerryEntry is the subset of a berry lockfile entry depscan needs.
type yarnBerryEntry struct {
	Version    string `yaml:"version"`
	Resolution string `yaml:"resolution"`
}

// parseYarnBerry reads a Yarn 2+ lockfile. Entry keys are descriptors such as
// "axios@npm:^1.6.0", and a single entry may list several comma-separated descriptors
// that resolved together.
func parseYarnBerry(raw []byte) ([]resolvedEntry, error) {
	var doc map[string]yarnBerryEntry
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("yarn.lock (berry): %w", err)
	}

	entries := make([]resolvedEntry, 0, len(doc))
	for key, entry := range doc {
		if key == "__metadata" {
			continue
		}
		name, ranges := yarnDescriptor(key)
		if name == "" || !isConcreteVersion(entry.Version) {
			continue
		}
		entries = append(entries, resolvedEntry{Name: name, Version: entry.Version, Ranges: ranges})
	}
	return entries, nil
}

// parseYarnV1 reads the Yarn 1 text format:
//
//	axios@^1.6.0, axios@^1.7.0:
//	  version "1.20.0"
//	  resolved "https://registry.yarnpkg.com/..."
//
// Only the `version` key at the first indent level is read; the nested dependencies
// block that may follow is ignored.
func parseYarnV1(raw []byte) []resolvedEntry {
	var entries []resolvedEntry
	var (
		pendingName   string
		pendingRanges []string
	)

	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)

	for sc.Scan() {
		line := sc.Text()
		if strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}

		// A descriptor block header sits at column zero and ends with a colon.
		if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") {
			pendingName, pendingRanges = yarnDescriptor(strings.TrimSuffix(strings.TrimSpace(line), ":"))
			continue
		}

		// Inside a block, take only the version at the first indent level so the
		// nested dependencies block cannot be mistaken for one.
		trimmed := strings.TrimSpace(line)
		indent := len(line) - len(strings.TrimLeft(line, " \t"))
		if pendingName != "" && indent <= 2 && strings.HasPrefix(trimmed, "version") {
			version := strings.TrimSpace(strings.TrimPrefix(trimmed, "version"))
			version = strings.Trim(version, `"' `)
			if isConcreteVersion(version) {
				entries = append(entries, resolvedEntry{Name: pendingName, Version: version, Ranges: pendingRanges})
			}
			pendingName = ""
		}
	}
	return entries
}

// yarnDescriptor extracts the package name and every requested range from one or more
// comma-separated yarn descriptors, handling both "axios@^1.6.0" and the berry
// "axios@npm:^1.6.0" shape, as well as scoped names. yarn.lock is keyed by what was
// asked for, not by install location, so the ranges are the only way to tell the
// project's own copy from one a dependency asked for.
func yarnDescriptor(key string) (name string, ranges []string) {
	for part := range strings.SplitSeq(key, ",") {
		n, r := splitNameVersion(strings.Trim(strings.TrimSpace(part), `"'`))
		if name == "" {
			name = n
		}
		if n == name && r != "" {
			ranges = append(ranges, r)
		}
	}
	return name, ranges
}
