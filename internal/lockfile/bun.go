package lockfile

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/pablorobert/depscan/internal/jsonc"
)

// bunLock is the subset of bun.lock depscan needs. The packages map holds
// heterogeneous tuples whose first element is the "name@version" identifier.
type bunLock struct {
	LockfileVersion int                          `json:"lockfileVersion"`
	Packages        map[string][]json.RawMessage `json:"packages"`
}

// parseBunText reads a text bun.lock. The file is JSONC — it carries trailing commas,
// so it must go through jsonc.Strip before encoding/json will accept it.
func parseBunText(path string) ([]resolvedEntry, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var lock bunLock
	if err := json.Unmarshal(jsonc.Strip(raw), &lock); err != nil {
		return nil, fmt.Errorf("bun.lock: %w", err)
	}

	entries := make([]resolvedEntry, 0, len(lock.Packages))
	for key, tuple := range lock.Packages {
		if len(tuple) == 0 {
			continue
		}
		var ident string
		if err := json.Unmarshal(tuple[0], &ident); err != nil {
			// Workspace entries can hold an object here instead of a string; the map
			// key is then the only name available and there is no resolved version.
			continue
		}
		name, version := splitNameVersion(ident)
		if name == "" {
			// Fall back to the map key, whose last segment is the package name for
			// nested resolutions such as "vite/esbuild".
			name = key
			if i := strings.LastIndexByte(key, '/'); i >= 0 && !strings.HasPrefix(key, "@") {
				name = key[i+1:]
			}
		}
		if !isConcreteVersion(stripPeerSuffix(version)) {
			continue
		}
		entries = append(entries, resolvedEntry{Name: name, Version: stripPeerSuffix(version)})
	}
	return entries, nil
}

// parseBunBinary handles the legacy binary bun.lockb, which depscan does not decode.
// It shells out to `bun pm ls --all` exactly once for the whole project — never once
// per dependency — and only when the caller allowed it. Verified with bun 1.4.2:
// the command reads from the lockfile without requiring node_modules and leaves the
// lockfile byte-identical.
func parseBunBinary(dir string, opts ParseOptions) ([]resolvedEntry, error) {
	if !opts.AllowBunSpawn {
		return nil, fmt.Errorf("bun.lockb is binary and the bun fallback is disabled")
	}
	bin, err := exec.LookPath("bun")
	if err != nil {
		return nil, fmt.Errorf("bun.lockb is binary and bun was not found in PATH")
	}

	timeout := time.Duration(opts.SpawnTimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// No shell, fixed argument vector, read-only subcommand.
	cmd := exec.CommandContext(ctx, bin, "pm", "ls", "--all")
	cmd.Dir = dir
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("bun pm ls timed out after %s", timeout)
		}
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return nil, fmt.Errorf("bun pm ls failed: %s", msg)
	}
	return parseBunPmLs(stdout.Bytes()), nil
}

// parseBunPmLs extracts name@version pairs from the tree `bun pm ls --all` prints.
// The first line is a header (the project path plus "node_modules"); every other line
// is a tree-drawing prefix followed by an identifier.
func parseBunPmLs(out []byte) []resolvedEntry {
	var entries []resolvedEntry
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)

	for sc.Scan() {
		line := sc.Text()
		// Drop the box-drawing prefix and any indentation.
		line = strings.TrimLeft(line, " │├└─\t")
		line = strings.TrimSpace(line)
		if line == "" || !strings.Contains(line, "@") {
			continue
		}
		// Skip the header line, which ends in "node_modules" possibly followed by an
		// installed count.
		if strings.Contains(line, "node_modules") {
			continue
		}
		name, version := splitNameVersion(line)
		version = stripPeerSuffix(version)
		if name == "" || !isConcreteVersion(version) {
			continue
		}
		entries = append(entries, resolvedEntry{Name: name, Version: version})
	}
	return entries
}
