package lockfile

import (
	"crypto/sha256"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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

// declaredOf builds the declared map a project.json would produce, so the adapters can
// be exercised without the project package.
func declaredOf(pairs map[string]string, category model.Category) map[string]Declared {
	out := make(map[string]Declared, len(pairs))
	for name, rng := range pairs {
		out[name] = Declared{Range: rng, Category: category}
	}
	return out
}

func find(deps []model.Dep, name string) (model.Dep, bool) {
	for _, d := range deps {
		if d.Name == name {
			return d, true
		}
	}
	return model.Dep{}, false
}

func findVersion(deps []model.Dep, name, version string) bool {
	for _, d := range deps {
		if d.Name == name && d.Version == version {
			return true
		}
	}
	return false
}

func TestDetectPrefersBunOverStaleNpmLock(t *testing.T) {
	dir := t.TempDir()
	for _, f := range []string{"bun.lock", "package-lock.json", "yarn.lock"} {
		if err := os.WriteFile(filepath.Join(dir, f), []byte("{}"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if got := Detect(dir); got != KindBunText {
		t.Fatalf("Detect = %q, want bun.lock", got)
	}
}

func TestDetectNone(t *testing.T) {
	if got := Detect(t.TempDir()); got != KindNone {
		t.Fatalf("Detect = %q, want empty", got)
	}
}

func TestKindManager(t *testing.T) {
	cases := map[Kind]string{
		KindBunText: "bun",
		KindBunBin:  "bun",
		KindNPM:     "npm",
		KindPNPM:    "pnpm",
		KindYarn:    "yarn",
		KindNone:    "unknown",
	}
	for kind, want := range cases {
		if got := kind.Manager(); got != want {
			t.Errorf("%q.Manager() = %q, want %q", kind, got, want)
		}
	}
}

func TestParseNoLockfile(t *testing.T) {
	_, err := Parse(fixture(t, "no-lockfile"), nil, ParseOptions{})
	if !errors.Is(err, ErrNoLockfile) {
		t.Fatalf("err = %v, want ErrNoLockfile", err)
	}
}

func TestParseBunText(t *testing.T) {
	declared := map[string]Declared{
		"axios": {Range: "^1.6.0", Category: model.CategoryProd},
		"vite":  {Range: "^5.0.0", Category: model.CategoryDev},
	}
	res, err := Parse(fixture(t, "bun-text"), declared, ParseOptions{})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if res.Kind != KindBunText {
		t.Fatalf("kind = %q", res.Kind)
	}

	axios, ok := find(res.Deps, "axios")
	if !ok {
		t.Fatal("axios missing")
	}
	if axios.Version != "1.6.0" || !axios.Direct || axios.Category != model.CategoryProd {
		t.Fatalf("axios = %+v", axios)
	}

	vite, _ := find(res.Deps, "vite")
	if vite.Category != model.CategoryDev {
		t.Fatalf("vite category = %q, want devDependency", vite.Category)
	}

	esbuild, ok := find(res.Deps, "esbuild")
	if !ok {
		t.Fatal("transitive esbuild missing")
	}
	if esbuild.Direct || esbuild.Category != "" {
		t.Fatalf("transitive dep must not be direct or categorized: %+v", esbuild)
	}
	if esbuild.CategoryOrNil() != nil {
		t.Fatal("transitive category must serialize as null")
	}
}

func TestParseNPMv3(t *testing.T) {
	declared := map[string]Declared{
		"axios": {Range: "^1.6.0", Category: model.CategoryProd},
		"vite":  {Range: "^5.0.0", Category: model.CategoryDev},
	}
	res, err := Parse(fixture(t, "npm-v3"), declared, ParseOptions{})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if _, ok := find(res.Deps, "@scope/helper"); !ok {
		t.Error("scoped package name was not recovered from the node_modules path")
	}
	if _, ok := find(res.Deps, "local-workspace"); ok {
		t.Error("a link entry is a workspace alias and must not be treated as installed")
	}
	if axios, _ := find(res.Deps, "axios"); axios.Version != "1.6.0" {
		t.Errorf("axios version = %q", axios.Version)
	}
}

func TestParseNPMv1(t *testing.T) {
	declared := map[string]Declared{"axios": {Range: "^1.6.0", Category: model.CategoryProd}}
	res, err := Parse(fixture(t, "npm-v1"), declared, ParseOptions{})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !findVersion(res.Deps, "axios", "1.6.0") {
		t.Error("axios 1.6.0 missing from the v1 dependency tree")
	}
	if !findVersion(res.Deps, "follow-redirects", "1.15.6") {
		t.Error("nested v1 dependency was not walked")
	}
}

func TestParseNPMNestedKeepsBothVersions(t *testing.T) {
	declared := map[string]Declared{
		"axios":           {Range: "^1.6.0", Category: model.CategoryProd},
		"legacy-consumer": {Range: "^1.0.0", Category: model.CategoryProd},
	}
	res, err := Parse(fixture(t, "npm-nested"), declared, ParseOptions{})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !findVersion(res.Deps, "axios", "1.6.0") || !findVersion(res.Deps, "axios", "0.27.2") {
		t.Fatalf("both axios versions must survive; got %+v", res.Deps)
	}
}

func TestParsePNPMv9StripsPeerSuffix(t *testing.T) {
	declared := map[string]Declared{
		"axios": {Range: "^1.6.0", Category: model.CategoryProd},
		"vite":  {Range: "^5.0.0", Category: model.CategoryDev},
	}
	res, err := Parse(fixture(t, "pnpm-v9"), declared, ParseOptions{})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	vite, ok := find(res.Deps, "vite")
	if !ok {
		t.Fatal("vite missing")
	}
	if vite.Version != "5.0.0" {
		t.Fatalf("vite version = %q, want 5.0.0 with the peer annotation stripped", vite.Version)
	}
	if _, ok := find(res.Deps, "@types/node"); !ok {
		t.Error("scoped key was not parsed")
	}
}

func TestParsePNPMv6KeyShapes(t *testing.T) {
	declared := map[string]Declared{
		"axios":         {Range: "^1.6.0", Category: model.CategoryProd},
		"@scope/helper": {Range: "^2.0.0", Category: model.CategoryProd},
	}
	res, err := Parse(fixture(t, "pnpm-v6"), declared, ParseOptions{})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !findVersion(res.Deps, "axios", "1.6.0") {
		t.Error(`"/axios@1.6.0" key shape not handled`)
	}
	if !findVersion(res.Deps, "@scope/helper", "2.1.0") {
		t.Error(`"/@scope/helper@2.1.0" key shape not handled`)
	}
	if !findVersion(res.Deps, "follow-redirects", "1.15.6") {
		t.Error(`legacy "/name/version" key shape not handled`)
	}

	// Regression: a peer annotation carries '@' of its own, so splitting the key
	// before stripping it lands inside the parentheses and drops the package. Found
	// against a real pnpm 6.0 lockfile, where it silently lost 11 direct dependencies.
	if !findVersion(res.Deps, "next", "14.1.2") {
		t.Errorf(`peer annotation broke the split for "next": %+v`, res.Deps)
	}
	if !findVersion(res.Deps, "@mui/material", "5.15.0") {
		t.Errorf(`peer annotation broke the split for a scoped name: %+v`, res.Deps)
	}
	for _, d := range res.Deps {
		if strings.ContainsAny(d.Name, "()") || strings.ContainsAny(d.Version, "()") {
			t.Errorf("peer annotation leaked into the parsed entry: %+v", d)
		}
	}
}

func TestParseYarnV1(t *testing.T) {
	declared := map[string]Declared{
		"axios":         {Range: "^1.6.0", Category: model.CategoryProd},
		"@scope/helper": {Range: "^2.0.0", Category: model.CategoryProd},
	}
	res, err := Parse(fixture(t, "yarn-v1"), declared, ParseOptions{})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !findVersion(res.Deps, "axios", "1.6.0") {
		t.Error("axios not parsed from a multi-descriptor block")
	}
	if !findVersion(res.Deps, "@scope/helper", "2.1.0") {
		t.Error("scoped quoted descriptor not parsed")
	}
	if !findVersion(res.Deps, "follow-redirects", "1.15.6") {
		t.Error("follow-redirects not parsed")
	}
	// The nested `dependencies:` block inside the axios entry lists
	// follow-redirects "^1.15.0"; that range must not be read as a version.
	if findVersion(res.Deps, "follow-redirects", "^1.15.0") {
		t.Error("a nested dependency range leaked in as a resolved version")
	}
}

func TestParseYarnBerry(t *testing.T) {
	declared := map[string]Declared{"axios": {Range: "^1.6.0", Category: model.CategoryProd}}
	res, err := Parse(fixture(t, "yarn-berry"), declared, ParseOptions{})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !findVersion(res.Deps, "axios", "1.6.0") {
		t.Errorf("axios missing from berry lockfile: %+v", res.Deps)
	}
	// The workspace self-entry resolves to 0.0.0-use.local and is not a registry
	// package, but it must not crash the parser.
	if _, ok := find(res.Deps, "__metadata"); ok {
		t.Error("__metadata was treated as a package")
	}
}

func TestParseDeclaredButMissingFromLockfileIsKept(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "bun.lock"),
		[]byte(`{"lockfileVersion":2,"packages":{}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	declared := map[string]Declared{"ghost": {Range: "^1.0.0", Category: model.CategoryProd}}

	res, err := Parse(dir, declared, ParseOptions{})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	ghost, ok := find(res.Deps, "ghost")
	if !ok {
		t.Fatal("a declared dependency absent from the lockfile must still be visible")
	}
	if ghost.Version != "" {
		t.Fatalf("version = %q, want empty so it is never mistaken for installed", ghost.Version)
	}
}

func TestParseMalformedLockfile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "bun.lock"), []byte("{not json at all"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(dir, nil, ParseOptions{}); err == nil {
		t.Fatal("expected an error for a malformed lockfile")
	}
}

// requireBun skips a test when bun is not installed. The binary bun.lockb path is the
// one place depscan needs an external program, so its tests are conditional.
func requireBun(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("bun"); err != nil {
		t.Skip("bun is not installed; the bun.lockb fallback cannot be exercised")
	}
}

func TestParseBunBinaryViaFallback(t *testing.T) {
	requireBun(t)
	dir := fixture(t, "bun-binary")

	if got := Detect(dir); got != KindBunBin {
		t.Fatalf("Detect = %q, want bun.lockb", got)
	}

	declared := map[string]Declared{
		"is-odd": {Range: "3.0.1", Category: model.CategoryProd},
	}
	res, err := Parse(dir, declared, ParseOptions{AllowBunSpawn: true, SpawnTimeoutSeconds: 30})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if res.Kind != KindBunBin {
		t.Fatalf("kind = %q", res.Kind)
	}

	odd, ok := find(res.Deps, "is-odd")
	if !ok {
		t.Fatalf("is-odd missing from %+v", res.Deps)
	}
	if odd.Version != "3.0.1" || !odd.Direct || odd.Category != model.CategoryProd {
		t.Fatalf("is-odd = %+v", odd)
	}

	// The tree also carries the transitive dependency, which must not be marked direct.
	num, ok := find(res.Deps, "is-number")
	if !ok {
		t.Fatalf("transitive is-number missing from %+v", res.Deps)
	}
	if num.Direct || num.Category != "" {
		t.Fatalf("is-number = %+v, want transitive", num)
	}
}

// TestBunBinaryFallbackDoesNotTouchTheLockfile covers the single spawn depscan is
// allowed to make: it must leave the project byte-identical.
func TestBunBinaryFallbackDoesNotTouchTheLockfile(t *testing.T) {
	requireBun(t)

	// Work on a copy so a mutation cannot damage the checked-in fixture.
	src := fixture(t, "bun-binary")
	dir := t.TempDir()
	entries, err := os.ReadDir(src)
	if err != nil {
		t.Fatal(err)
	}
	before := map[string][32]byte{}
	for _, e := range entries {
		data, err := os.ReadFile(filepath.Join(src, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, e.Name()), data, 0o644); err != nil {
			t.Fatal(err)
		}
		before[e.Name()] = sha256.Sum256(data)
	}

	if _, err := Parse(dir, nil, ParseOptions{AllowBunSpawn: true, SpawnTimeoutSeconds: 30}); err != nil {
		t.Fatalf("Parse: %v", err)
	}

	after, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) {
		t.Fatalf("the spawn changed the file listing: %d files, want %d", len(after), len(before))
	}
	for name, sum := range before {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if sha256.Sum256(data) != sum {
			t.Errorf("%s was modified by the bun fallback", name)
		}
	}
}

func TestBinaryBunLockWithoutFallback(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "bun.lockb"), []byte{0x00, 0x01}, 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Parse(dir, nil, ParseOptions{AllowBunSpawn: false})
	if err == nil {
		t.Fatal("expected an error when the bun fallback is disabled")
	}
}

func TestParseBunPmLsOutput(t *testing.T) {
	// Shape verified against bun 1.4.2.
	out := []byte("C:\\projects\\app node_modules (88 installed)\n" +
		"├── axios@1.6.0\n" +
		"├── @scope/helper@2.1.0\n" +
		"└── vite@5.0.0\n")

	entries := parseBunPmLs(out)
	got := map[string]string{}
	for _, e := range entries {
		got[e.Name] = e.Version
	}
	for name, want := range map[string]string{
		"axios":         "1.6.0",
		"@scope/helper": "2.1.0",
		"vite":          "5.0.0",
	} {
		if got[name] != want {
			t.Errorf("%s = %q, want %q (parsed %+v)", name, got[name], want, entries)
		}
	}
	if len(entries) != 3 {
		t.Errorf("parsed %d entries, want 3 (the header must be skipped): %+v", len(entries), entries)
	}
}

func TestSplitNameVersion(t *testing.T) {
	cases := []struct{ in, name, version string }{
		{"axios@1.6.0", "axios", "1.6.0"},
		{"@scope/pkg@2.1.0", "@scope/pkg", "2.1.0"},
		{"@scope/pkg", "@scope/pkg", ""},
		{"plain", "plain", ""},
		{"", "", ""},
	}
	for _, c := range cases {
		name, version := splitNameVersion(c.in)
		if name != c.name || version != c.version {
			t.Errorf("splitNameVersion(%q) = (%q, %q), want (%q, %q)",
				c.in, name, version, c.name, c.version)
		}
	}
}

func TestIsConcreteVersion(t *testing.T) {
	concrete := []string{"1.0.0", "0.21.5", "1.6.0-beta.1"}
	abstract := []string{"", "workspace:*", "file:../x", "link:../y", "npm:other@1.0.0", "^1.0.0", "git+https://x"}

	for _, v := range concrete {
		if !isConcreteVersion(v) {
			t.Errorf("%q should be concrete", v)
		}
	}
	for _, v := range abstract {
		if isConcreteVersion(v) {
			t.Errorf("%q should not be concrete", v)
		}
	}
}

func TestStripPeerSuffix(t *testing.T) {
	if got := stripPeerSuffix("5.4.21(@types/node@20.0.0)"); got != "5.4.21" {
		t.Fatalf("got %q", got)
	}
	if got := stripPeerSuffix("1.0.0"); got != "1.0.0" {
		t.Fatalf("got %q", got)
	}
}
