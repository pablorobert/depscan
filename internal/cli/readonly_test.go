package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/pablorobert/depscan/internal/model"
)

// fakeNPM answers every endpoint a full scan touches, so the read-only guarantee is
// verified on the complete code path rather than only in offline mode.
func fakeNPM(t *testing.T) *httptest.Server {
	t.Helper()
	// 9.9.9 was published just now, so a minimum release age holds it back and 1.7.0
	// is the newest installable version.
	recent := time.Now().UTC().Format(time.RFC3339)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/security/advisories/bulk"):
			var req map[string][]string
			_ = json.NewDecoder(r.Body).Decode(&req)
			// axios is a direct dependency and esbuild a transitive one, so the
			// grouping in the terminal output is genuinely exercised.
			parts := []string{}
			if _, ok := req["axios"]; ok {
				parts = append(parts, `"axios":[{"id":1,"url":"https://github.com/advisories/GHSA-test","title":"t","severity":"high","vulnerable_versions":">=1.0.0 <1.8.0","cwe":["CWE-1"],"cvss":{"score":7.5,"vectorString":null}}]`)
			}
			if _, ok := req["esbuild"]; ok {
				parts = append(parts, `"esbuild":[{"id":2,"url":"https://github.com/advisories/GHSA-test2","title":"t2","severity":"moderate","vulnerable_versions":"<=0.24.2","cwe":["CWE-2"],"cvss":{"score":5.3,"vectorString":null}}]`)
			}
			fmt.Fprintf(w, "{%s}", strings.Join(parts, ","))

		case strings.HasSuffix(r.URL.Path, "/dist-tags"):
			fmt.Fprint(w, `{"latest":"9.9.9"}`)

		default:
			fmt.Fprintf(w, `{"versions":{"1.6.0":{},"1.7.0":{},"9.9.9":{}},`+
				`"time":{"1.6.0":"2020-01-01T00:00:00Z","1.7.0":"2020-06-01T00:00:00Z","9.9.9":%q}}`, recent)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestBunMinimumReleaseAgeMarksHeldBackLatest scans a bun project whose bunfig.toml
// sets a window: latest is marked the way bun outdated marks it, and the version bun
// would actually install is named.
func TestBunMinimumReleaseAgeMarksHeldBackLatest(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	srv := fakeNPM(t)

	root := t.TempDir()
	copyTree(t, filepath.Join("..", "..", "testdata", "fixtures", "bun-text"), root)
	if err := os.WriteFile(filepath.Join(root, "bunfig.toml"),
		[]byte("[install]\nminimumReleaseAge = 259200\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	run := func(args ...string) string {
		cfg, err := Parse(append(args, "--no-cache", root), io.Discard)
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		cfg.RegistryBaseURL = srv.URL
		cfg.AdvisoryBaseURL = srv.URL
		var stdout, stderr bytes.Buffer
		Run(cfg, &stdout, &stderr)
		return stdout.String()
	}

	var rep model.Report
	if err := json.Unmarshal([]byte(run("--json")), &rep); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	p := rep.Projects[0]
	if p.MinimumReleaseAge == nil || p.MinimumReleaseAge.Seconds != 259200 {
		t.Fatalf("minimumReleaseAge = %+v, want 259200 from the project bunfig", p.MinimumReleaseAge)
	}
	var axios *model.OutdatedPackage
	for i := range p.Outdated.Packages {
		if p.Outdated.Packages[i].Name == "axios" {
			axios = &p.Outdated.Packages[i]
		}
	}
	if axios == nil || axios.ReleaseAge == nil {
		t.Fatalf("axios release age missing: %+v", axios)
	}
	if axios.ReleaseAge.Status != model.ReleaseAgeHeldBack {
		t.Fatalf("status = %q, want held-back", axios.ReleaseAge.Status)
	}
	if axios.ReleaseAge.Eligible == nil || *axios.ReleaseAge.Eligible != "1.7.0" {
		t.Fatalf("eligible = %v, want 1.7.0", axios.ReleaseAge.Eligible)
	}

	text := run()
	for _, want := range []string{"9.9.9*", "installable: 1.7.0", "published less than 72h ago"} {
		if !strings.Contains(text, want) {
			t.Errorf("terminal output is missing %q\n---\n%s", want, text)
		}
	}
}

// hashTree fingerprints every file under root: relative path, size and content.
func hashTree(t *testing.T, root string) string {
	t.Helper()

	type entry struct {
		rel  string
		size int64
		sum  string
	}
	var entries []entry

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		sum := sha256.Sum256(data)
		entries = append(entries, entry{
			rel:  filepath.ToSlash(rel),
			size: int64(len(data)),
			sum:  hex.EncodeToString(sum[:]),
		})
		return nil
	})
	if err != nil {
		t.Fatalf("hashTree: %v", err)
	}

	sort.Slice(entries, func(i, j int) bool { return entries[i].rel < entries[j].rel })

	h := sha256.New()
	for _, e := range entries {
		fmt.Fprintf(h, "%s|%d|%s\n", e.rel, e.size, e.sum)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// copyTree duplicates the fixtures so the test scans a throwaway copy. A mutation
// would then be caught without risking the checked-in fixtures.
func copyTree(t *testing.T, src, dst string) {
	t.Helper()
	err := filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o644)
	})
	if err != nil {
		t.Fatalf("copyTree: %v", err)
	}
}

// TestScanNeverModifiesTheScannedProjects is the guarantee from SPEC.md section 16:
// a recursive fingerprint of the tree must be identical before and after a full scan.
func TestScanNeverModifiesTheScannedProjects(t *testing.T) {
	root := t.TempDir()
	copyTree(t, filepath.Join("..", "..", "testdata", "fixtures"), root)

	before := hashTree(t, root)

	srv := fakeNPM(t)
	cfg, err := Parse([]string{"--json", "--no-cache", "--wanted", root}, io.Discard)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	cfg.RegistryBaseURL = srv.URL
	cfg.AdvisoryBaseURL = srv.URL

	var stdout, stderr bytes.Buffer
	Run(cfg, &stdout, &stderr)

	after := hashTree(t, root)
	if before != after {
		t.Fatalf("the scanned tree changed:\nbefore %s\nafter  %s", before, after)
	}

	// Guard against the fingerprint passing because nothing was actually analysed.
	var rep model.Report
	if err := json.Unmarshal(stdout.Bytes(), &rep); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if rep.Summary.OutdatedPackages == 0 {
		t.Error("no outdated package was reported; the read-only check did not exercise the scan")
	}
	if rep.Summary.VulnerablePackages == 0 {
		t.Error("no vulnerability was reported; the security path did not run")
	}
}

func TestFullScanReportsBothAxesAndKeepsStdoutClean(t *testing.T) {
	srv := fakeNPM(t)
	cfg, err := Parse([]string{
		"--json", "--no-cache", filepath.Join("..", "..", "testdata", "fixtures", "bun-text"),
	}, io.Discard)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	cfg.RegistryBaseURL = srv.URL
	cfg.AdvisoryBaseURL = srv.URL

	var stdout, stderr bytes.Buffer
	code := Run(cfg, &stdout, &stderr)

	var rep model.Report
	if err := json.Unmarshal(stdout.Bytes(), &rep); err != nil {
		t.Fatalf("stdout must hold exactly one JSON document: %v\n%s", err, stdout.String())
	}
	if len(rep.Projects) != 1 {
		t.Fatalf("projects = %d, want 1", len(rep.Projects))
	}

	p := rep.Projects[0]
	if p.Outdated.Status != model.StatusFindings {
		t.Errorf("outdated status = %q, want findings", p.Outdated.Status)
	}
	if p.Security.Status != model.StatusFindings {
		t.Errorf("security status = %q, want findings", p.Security.Status)
	}
	if !p.FullyAnalyzed() {
		t.Error("both axes reached a verdict, so the project is fully analyzed")
	}

	var axios *model.VulnerablePackage
	for i := range p.Security.Packages {
		if p.Security.Packages[i].Name == "axios" {
			axios = &p.Security.Packages[i]
		}
	}
	if axios == nil {
		t.Fatal("axios finding missing")
	}
	if axios.FixedVersion == nil || *axios.FixedVersion != "1.8.0" {
		t.Errorf("fixedVersion = %v, want 1.8.0 inferred from the range", axios.FixedVersion)
	}
	if !axios.FixedInferred {
		t.Error("fixedVersionInferred must be true")
	}
	if code != ExitFindings {
		t.Errorf("exit = %d, want 1", code)
	}
}

func TestTerminalOutputIsReadableWithoutColor(t *testing.T) {
	t.Setenv("NO_COLOR", "1")

	srv := fakeNPM(t)
	cfg, err := Parse([]string{
		"--no-cache", filepath.Join("..", "..", "testdata", "fixtures", "bun-text"),
	}, io.Discard)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	cfg.RegistryBaseURL = srv.URL
	cfg.AdvisoryBaseURL = srv.URL

	var stdout, stderr bytes.Buffer
	Run(cfg, &stdout, &stderr)
	text := stdout.String()

	if strings.Contains(text, "\033[") {
		t.Error("ANSI escapes leaked into a non-terminal, NO_COLOR destination")
	}
	for _, want := range []string{
		"fixture-bun-text", "outdated", "HIGH", "direct", "transitive",
		"Projects:", "Affected packages:", "Completed in",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("terminal output is missing %q\n---\n%s", want, text)
		}
	}
}
