// Package scanner walks a directory tree and discovers projects.
package scanner

import (
	"io/fs"
	"os"
	"path/filepath"
	"sort"
)

// skipDirs are never traversed. Detection still works inside a project that contains
// node_modules: the exclusion is about traversal, not about finding package.json.
// Kept deliberately short — an aggressive list hides real projects.
var skipDirs = map[string]bool{
	"node_modules": true,
	".git":         true,
}

// Result is the outcome of a walk.
type Result struct {
	// Dirs holds every directory containing a package.json, sorted.
	Dirs []string
	// SkippedSymlinks lists directory symlinks that were not followed, so a cyclic
	// link cannot hang the scan.
	SkippedSymlinks []string
	// Unreadable lists directories that could not be read.
	Unreadable []string
}

// Walk searches root recursively for directories containing a package.json.
func Walk(root string) (*Result, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	if st, err := os.Stat(abs); err != nil {
		return nil, err
	} else if !st.IsDir() {
		return nil, &fs.PathError{Op: "scan", Path: abs, Err: fs.ErrInvalid}
	}

	res := &Result{}
	walkErr := filepath.WalkDir(abs, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// An unreadable directory is recorded and skipped, never fatal.
			res.Unreadable = append(res.Unreadable, path)
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}

		// WalkDir does not follow symlinks: a directory symlink arrives as a
		// non-directory entry. Record it so the skip is visible rather than silent.
		if d.Type()&fs.ModeSymlink != 0 {
			if st, statErr := os.Stat(path); statErr == nil && st.IsDir() {
				res.SkippedSymlinks = append(res.SkippedSymlinks, path)
			}
			return nil
		}

		if d.IsDir() {
			if path != abs && skipDirs[d.Name()] {
				return fs.SkipDir
			}
			return nil
		}

		if d.Name() == "package.json" {
			res.Dirs = append(res.Dirs, filepath.Dir(path))
		}
		return nil
	})
	if walkErr != nil {
		return res, walkErr
	}

	sort.Strings(res.Dirs)
	return res, nil
}

// NearestWorkspaceRoot returns the closest ancestor of dir that is present in roots,
// or an empty string. Used to tag workspace members without resolving the workspace.
func NearestWorkspaceRoot(dir string, roots map[string]bool) string {
	cur := filepath.Dir(dir)
	for {
		if roots[cur] {
			return cur
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return ""
		}
		cur = parent
	}
}
