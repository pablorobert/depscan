// Package bunfig reads the one bunfig.toml setting depscan needs: the install
// minimum release age, which makes bun ignore versions published too recently.
//
// Only the [install] keys minimumReleaseAge and minimumReleaseAgeExcludes are read.
// A general TOML parser would be a dependency for two keys, so this is a line reader
// that understands the shapes bun documents: an integer (seconds, underscores
// allowed) and an array of strings, which may span several lines.
package bunfig

import (
	"bufio"
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

// Policy is the effective minimum release age for one project.
type Policy struct {
	// Seconds is the window; a version published less than this long ago is skipped.
	Seconds int64
	// Excludes lists packages the window does not apply to.
	Excludes []string
	// Source is the bunfig.toml the window came from.
	Source string
}

// Excluded reports whether name is exempt from the window.
func (p *Policy) Excluded(name string) bool {
	return slices.Contains(p.Excludes, name)
}

// settings is what one file says. A nil field means the file does not set the key,
// so a project file can override one key and inherit the other from the global file.
type settings struct {
	seconds  *int64
	excludes *[]string
}

// Load returns the policy in effect for a project, or nil when no window is set.
// The project's own bunfig.toml wins over the global one key by key, the way bun
// merges them. globalPath may be empty to skip the global file.
func Load(projectDir, globalPath string) (*Policy, error) {
	local, err := readFile(filepath.Join(projectDir, "bunfig.toml"))
	if err != nil {
		return nil, err
	}
	var global settings
	if globalPath != "" {
		if global, err = readFile(globalPath); err != nil {
			return nil, err
		}
	}

	p := &Policy{}
	switch {
	case local.seconds != nil:
		p.Seconds = *local.seconds
		p.Source = filepath.Join(projectDir, "bunfig.toml")
	case global.seconds != nil:
		p.Seconds = *global.seconds
		p.Source = globalPath
	}
	if p.Seconds <= 0 {
		return nil, nil
	}
	switch {
	case local.excludes != nil:
		p.Excludes = *local.excludes
	case global.excludes != nil:
		p.Excludes = *global.excludes
	}
	return p, nil
}

// GlobalPath returns the global bunfig bun reads: $XDG_CONFIG_HOME/.bunfig.toml when
// that variable is set, otherwise ~/.bunfig.toml. Empty when neither can be resolved.
func GlobalPath() string {
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		return filepath.Join(xdg, ".bunfig.toml")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".bunfig.toml")
}

// readFile parses one bunfig.toml. A missing file sets nothing.
func readFile(path string) (settings, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return settings{}, nil
	}
	if err != nil {
		return settings{}, err
	}
	return parse(raw), nil
}

// parse extracts the two keys, either inside an [install] table or dotted at the top
// level ("install.minimumReleaseAge = ..."). Anything else is ignored.
func parse(raw []byte) settings {
	var (
		out     settings
		section string
		// pendingArray collects a multi-line array until its closing bracket.
		pendingArray *strings.Builder
		pendingKey   string
	)

	sc := bufio.NewScanner(bytes.NewReader(raw))
	for sc.Scan() {
		line := strings.TrimSpace(stripComment(sc.Text()))

		if pendingArray != nil {
			pendingArray.WriteString(" ")
			pendingArray.WriteString(line)
			if strings.Contains(line, "]") {
				out.set(pendingKey, pendingArray.String())
				pendingArray = nil
			}
			continue
		}
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") {
			section = strings.TrimSpace(strings.Trim(line, "[]"))
			continue
		}

		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.Trim(strings.TrimSpace(key), `"`)
		value = strings.TrimSpace(value)
		if section != "" {
			key = section + "." + key
		}
		if key != "install.minimumReleaseAge" && key != "install.minimumReleaseAgeExcludes" {
			continue
		}
		if strings.HasPrefix(value, "[") && !strings.Contains(value, "]") {
			pendingArray = &strings.Builder{}
			pendingArray.WriteString(value)
			pendingKey = key
			continue
		}
		out.set(key, value)
	}
	return out
}

func (s *settings) set(key, value string) {
	switch key {
	case "install.minimumReleaseAge":
		if n, err := strconv.ParseInt(strings.ReplaceAll(value, "_", ""), 10, 64); err == nil {
			s.seconds = &n
		}
	case "install.minimumReleaseAgeExcludes":
		list := parseStringArray(value)
		s.excludes = &list
	}
}

// parseStringArray reads `["a", 'b', "c",]`.
func parseStringArray(value string) []string {
	value = strings.TrimSpace(value)
	value = strings.TrimPrefix(value, "[")
	value = strings.TrimSuffix(value, "]")
	out := []string{}
	for item := range strings.SplitSeq(value, ",") {
		item = strings.Trim(strings.TrimSpace(item), `"'`)
		if item != "" {
			out = append(out, item)
		}
	}
	return out
}

// stripComment drops a trailing "# ..." that is not inside a quoted string. Package
// names never contain '#', so tracking quotes is enough.
func stripComment(line string) string {
	var quote rune
	for i, r := range line {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			}
		case r == '"' || r == '\'':
			quote = r
		case r == '#':
			return line[:i]
		}
	}
	return line
}
