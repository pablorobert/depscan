package scanner

import (
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"
)

func TestWalkFindsIndependentProjects(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "fixtures")
	res, err := Walk(root)
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}

	abs, err := filepath.Abs(root)
	if err != nil {
		t.Fatal(err)
	}
	has := func(rel string) bool {
		return slices.Contains(res.Dirs, filepath.Join(abs, filepath.FromSlash(rel)))
	}

	for _, want := range []string{
		"bun-text", "npm-v3", "npm-v1", "pnpm-v9", "pnpm-v6",
		"yarn-v1", "yarn-berry", "no-lockfile", "malformed",
		"nested/outer", "nested/outer/inner",
		"workspace-root", "workspace-root/packages/member",
		"with-node-modules",
	} {
		if !has(want) {
			t.Errorf("project %s was not discovered", want)
		}
	}
}

func TestWalkDoesNotTraverseNodeModules(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "fixtures", "with-node-modules")
	res, err := Walk(root)
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}

	// The project itself is found even though it contains node_modules, and the
	// installed package.json inside node_modules is not reported as a project.
	if len(res.Dirs) != 1 {
		t.Fatalf("found %d projects, want 1: %v", len(res.Dirs), res.Dirs)
	}
	for _, d := range res.Dirs {
		if filepath.Base(filepath.Dir(d)) == "node_modules" {
			t.Errorf("node_modules was traversed: %s", d)
		}
	}
}

func TestWalkSkipsGitDirectory(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "package.json"), "{}")
	mustWrite(t, filepath.Join(root, ".git", "package.json"), "{}")

	res, err := Walk(root)
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if len(res.Dirs) != 1 {
		t.Fatalf("found %d projects, want 1: %v", len(res.Dirs), res.Dirs)
	}
}

func TestWalkDoesNotFollowSymlinkCycle(t *testing.T) {
	if runtime.GOOS == "windows" {
		// Creating a directory symlink needs elevation or developer mode here.
		t.Skip("symlink creation requires privileges on Windows")
	}
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "a", "package.json"), "{}")
	if err := os.Symlink(root, filepath.Join(root, "a", "loop")); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}

	res, err := Walk(root)
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if len(res.Dirs) != 1 {
		t.Fatalf("found %d projects, want 1: %v", len(res.Dirs), res.Dirs)
	}
	if len(res.SkippedSymlinks) != 1 {
		t.Fatalf("skipped symlinks = %v, want the loop recorded", res.SkippedSymlinks)
	}
}

func TestWalkRootIsNotAssumedToBeAProject(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "child", "package.json"), "{}")

	res, err := Walk(root)
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	abs, _ := filepath.Abs(root)
	if slices.Contains(res.Dirs, abs) {
		t.Error("the root has no package.json and must not be reported as a project")
	}
	if len(res.Dirs) != 1 {
		t.Fatalf("found %d projects, want 1", len(res.Dirs))
	}
}

func TestWalkRejectsFileAndMissingRoot(t *testing.T) {
	file := filepath.Join(t.TempDir(), "f")
	mustWrite(t, file, "x")
	if _, err := Walk(file); err == nil {
		t.Error("walking a file should fail")
	}
	if _, err := Walk(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Error("walking a missing directory should fail")
	}
}

func TestNearestWorkspaceRoot(t *testing.T) {
	root := filepath.FromSlash("/repo/ws")
	member := filepath.FromSlash("/repo/ws/packages/member")
	outside := filepath.FromSlash("/other/app")
	roots := map[string]bool{root: true}

	if got := NearestWorkspaceRoot(member, roots); got != root {
		t.Errorf("member root = %q, want %q", got, root)
	}
	if got := NearestWorkspaceRoot(outside, roots); got != "" {
		t.Errorf("unrelated project root = %q, want empty", got)
	}
	if got := NearestWorkspaceRoot(root, roots); got != "" {
		t.Errorf("a workspace root is not its own member, got %q", got)
	}
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
