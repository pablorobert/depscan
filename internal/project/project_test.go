package project

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/pablorobert/depscan/internal/model"
)

func fixture(t *testing.T, name string) string {
	t.Helper()
	dir := filepath.Join("..", "..", "testdata", "fixtures", name)
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("fixture %s missing: %v", name, err)
	}
	return dir
}

func depNamed(p *model.Project, name string) (model.Dep, bool) {
	for _, d := range p.Deps {
		if d.Name == name {
			return d, true
		}
	}
	return model.Dep{}, false
}

func TestLoadBunProject(t *testing.T) {
	p := Load(fixture(t, "bun-text"), LoadOptions{})

	if p.Name != "fixture-bun-text" {
		t.Errorf("name = %q", p.Name)
	}
	if p.PackageManager != "bun" {
		t.Errorf("packageManager = %q, want bun", p.PackageManager)
	}
	if p.Lockfile != "bun.lock" {
		t.Errorf("lockfile = %q", p.Lockfile)
	}
	if len(p.Errors) != 0 {
		t.Errorf("errors = %+v, want none", p.Errors)
	}

	axios, ok := depNamed(p, "axios")
	if !ok {
		t.Fatal("axios missing")
	}
	if axios.Declared != "^1.6.0" || axios.Version != "1.6.0" {
		t.Errorf("axios = %+v", axios)
	}
	if axios.Category != model.CategoryProd {
		t.Errorf("axios category = %q", axios.Category)
	}

	vite, _ := depNamed(p, "vite")
	if vite.Category != model.CategoryDev {
		t.Errorf("vite category = %q, want devDependency", vite.Category)
	}
}

func TestLoadDetectsEachPackageManager(t *testing.T) {
	cases := map[string]struct{ manager, lockfile string }{
		"npm-v3":     {"npm", "package-lock.json"},
		"pnpm-v9":    {"pnpm", "pnpm-lock.yaml"},
		"yarn-v1":    {"yarn", "yarn.lock"},
		"yarn-berry": {"yarn", "yarn.lock"},
	}
	for name, want := range cases {
		t.Run(name, func(t *testing.T) {
			p := Load(fixture(t, name), LoadOptions{})
			if p.PackageManager != want.manager {
				t.Errorf("packageManager = %q, want %q", p.PackageManager, want.manager)
			}
			if p.Lockfile != want.lockfile {
				t.Errorf("lockfile = %q, want %q", p.Lockfile, want.lockfile)
			}
			if len(p.Errors) != 0 {
				t.Errorf("errors = %+v", p.Errors)
			}
		})
	}
}

func TestLoadNoLockfileIsAnErrorNotAGuess(t *testing.T) {
	p := Load(fixture(t, "no-lockfile"), LoadOptions{})

	if p.PackageManager != "unknown" {
		t.Errorf("packageManager = %q, want unknown", p.PackageManager)
	}
	if p.Outdated.Status != model.StatusError || p.Security.Status != model.StatusError {
		t.Errorf("statuses = %q / %q, want error on both", p.Outdated.Status, p.Security.Status)
	}
	if len(p.Errors) != 1 || p.Errors[0].Kind != model.ErrNoLockfile {
		t.Fatalf("errors = %+v, want a single no_lockfile entry", p.Errors)
	}
	if len(p.Deps) != 0 {
		t.Errorf("deps = %+v: without a lockfile no version may be assumed", p.Deps)
	}
}

func TestLoadMalformedPackageJSON(t *testing.T) {
	p := Load(fixture(t, "malformed"), LoadOptions{})

	if len(p.Errors) != 1 || p.Errors[0].Kind != model.ErrParsePackageJSON {
		t.Fatalf("errors = %+v, want parse_package_json", p.Errors)
	}
	if p.Errors[0].Phase != model.PhaseDiscovery {
		t.Errorf("phase = %q, want discovery", p.Errors[0].Phase)
	}
	if p.Outdated.Status != model.StatusError || p.Security.Status != model.StatusError {
		t.Error("both axes must report error")
	}
	// The project name falls back to the directory, so the failure is still
	// attributable in the report.
	if p.Name == "" {
		t.Error("a project with an unparseable package.json still needs a label")
	}
}

func TestLoadMissingPackageJSON(t *testing.T) {
	p := Load(t.TempDir(), LoadOptions{})
	if len(p.Errors) != 1 || p.Errors[0].Kind != model.ErrParsePackageJSON {
		t.Fatalf("errors = %+v", p.Errors)
	}
}

func TestDependencySectionPrecedence(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "package.json"), `{
	  "name": "dup",
	  "dependencies": { "shared": "^1.0.0" },
	  "devDependencies": { "shared": "^2.0.0", "onlydev": "^3.0.0" },
	  "peerDependencies": { "peered": "^4.0.0" },
	  "optionalDependencies": { "maybe": "^5.0.0" }
	}`)
	mustWrite(t, filepath.Join(dir, "bun.lock"), `{
	  "lockfileVersion": 2,
	  "packages": {
	    "shared": ["shared@1.4.0", "", {}, "sha512-x=="],
	    "onlydev": ["onlydev@3.1.0", "", {}, "sha512-y=="],
	    "peered": ["peered@4.0.1", "", {}, "sha512-z=="],
	    "maybe": ["maybe@5.0.2", "", {}, "sha512-w=="],
	  }
	}`)

	p := Load(dir, LoadOptions{})

	shared, _ := depNamed(p, "shared")
	if shared.Category != model.CategoryProd {
		t.Errorf("a package in both sections is a runtime dependency; got %q", shared.Category)
	}
	if shared.Declared != "^1.0.0" {
		t.Errorf("declared = %q, want the dependencies range", shared.Declared)
	}

	for name, want := range map[string]model.Category{
		"onlydev": model.CategoryDev,
		"peered":  model.CategoryPeer,
		"maybe":   model.CategoryOptional,
	} {
		d, ok := depNamed(p, name)
		if !ok {
			t.Errorf("%s missing", name)
			continue
		}
		if d.Category != want {
			t.Errorf("%s category = %q, want %q", name, d.Category, want)
		}
	}
}

func TestIsWorkspaceRoot(t *testing.T) {
	if !IsWorkspaceRoot(fixture(t, "workspace-root")) {
		t.Error("a package.json declaring workspaces is a workspace root")
	}
	if IsWorkspaceRoot(fixture(t, "bun-text")) {
		t.Error("a plain project is not a workspace root")
	}
	if IsWorkspaceRoot(fixture(t, "malformed")) {
		t.Error("an unparseable package.json must not be reported as a workspace root")
	}
	if IsWorkspaceRoot(t.TempDir()) {
		t.Error("a directory with no package.json is not a workspace root")
	}
}

func TestWorkspaceMemberKeepsNonRegistryDeclarations(t *testing.T) {
	p := Load(fixture(t, filepath.Join("workspace-root", "packages", "member")), LoadOptions{})
	if len(p.Errors) != 0 {
		t.Fatalf("errors = %+v", p.Errors)
	}

	sibling, ok := depNamed(p, "sibling")
	if !ok {
		t.Fatal("the workspace sibling declaration must survive")
	}
	if sibling.Declared != "workspace:*" {
		t.Errorf("declared = %q", sibling.Declared)
	}
	if sibling.Version != "" {
		t.Errorf("version = %q: a workspace alias has no registry version", sibling.Version)
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
