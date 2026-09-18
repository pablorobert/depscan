package bunfig

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func write(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestParseInstallTable(t *testing.T) {
	s := parse([]byte(`
[test]
preload = ["./happydom.js"]

[install]
# Supply chain: só instala pacote publicado há >= 72h.
minimumReleaseAge = 259_200 # three days
minimumReleaseAgeExcludes = [
  "@types/node", # trusted
  'typescript',
]
`))
	if s.seconds == nil || *s.seconds != 259200 {
		t.Fatalf("seconds = %v, want 259200", s.seconds)
	}
	if s.excludes == nil || !reflect.DeepEqual(*s.excludes, []string{"@types/node", "typescript"}) {
		t.Fatalf("excludes = %v", s.excludes)
	}
}

func TestParseDottedKeyAndOtherTablesIgnored(t *testing.T) {
	s := parse([]byte(`install.minimumReleaseAge = 60
[test]
minimumReleaseAge = 999
`))
	if s.seconds == nil || *s.seconds != 60 {
		t.Fatalf("seconds = %v, want 60: a key under another table must not count", s.seconds)
	}
}

func TestLoadProjectOverridesGlobalKeyByKey(t *testing.T) {
	dir := t.TempDir()
	global := write(t, t.TempDir(), ".bunfig.toml",
		"[install]\nminimumReleaseAge = 259200\nminimumReleaseAgeExcludes = [\"zod\"]\n")
	write(t, dir, "bunfig.toml", "[install]\nminimumReleaseAge = 3600\n")

	p, err := Load(dir, global)
	if err != nil {
		t.Fatal(err)
	}
	if p == nil || p.Seconds != 3600 {
		t.Fatalf("policy = %+v, want the project's 3600", p)
	}
	if p.Source != filepath.Join(dir, "bunfig.toml") {
		t.Fatalf("source = %q", p.Source)
	}
	if !p.Excluded("zod") {
		t.Fatal("excludes not set by the project must be inherited from the global file")
	}
}

func TestLoadGlobalOnly(t *testing.T) {
	global := write(t, t.TempDir(), ".bunfig.toml", "[install]\nminimumReleaseAge = 259200\n")
	p, err := Load(t.TempDir(), global)
	if err != nil {
		t.Fatal(err)
	}
	if p == nil || p.Seconds != 259200 || p.Source != global {
		t.Fatalf("policy = %+v", p)
	}
}

func TestLoadNoWindow(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "bunfig.toml", "[install]\nsaveTextLockfile = false\n")
	p, err := Load(dir, filepath.Join(t.TempDir(), "missing.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if p != nil {
		t.Fatalf("policy = %+v, want nil", p)
	}
}

func TestLoadZeroDisablesGlobalWindow(t *testing.T) {
	dir := t.TempDir()
	global := write(t, t.TempDir(), ".bunfig.toml", "[install]\nminimumReleaseAge = 259200\n")
	write(t, dir, "bunfig.toml", "[install]\nminimumReleaseAge = 0\n")
	p, err := Load(dir, global)
	if err != nil {
		t.Fatal(err)
	}
	if p != nil {
		t.Fatalf("policy = %+v, want nil: the project turned the window off", p)
	}
}
