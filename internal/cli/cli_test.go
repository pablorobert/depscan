package cli

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/pablorobert/depscan/internal/model"
)

func TestParseDefaults(t *testing.T) {
	cfg, err := Parse([]string{"/projects"}, io.Discard)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.Root != "/projects" {
		t.Errorf("root = %q", cfg.Root)
	}
	if cfg.Concurrency != 64 {
		t.Errorf("concurrency = %d, want the polite default of 64", cfg.Concurrency)
	}
	if cfg.Timeout != 15*time.Second {
		t.Errorf("timeout = %v", cfg.Timeout)
	}
	if cfg.Wanted {
		t.Error("--wanted must be off by default: it costs one packument per major-behind package")
	}
	if cfg.FailOn != model.SeverityLow {
		t.Errorf("fail-on = %q, want low so any vulnerability fails", cfg.FailOn)
	}
	if cfg.FailOnOutdated {
		t.Error("outdated must not fail the build by default")
	}
}

func TestParseRejections(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"no directory", []string{}},
		{"two directories", []string{"/a", "/b"}},
		{"mutually exclusive scopes", []string{"--only-outdated", "--only-vulnerable", "/a"}},
		{"concurrency too low", []string{"--concurrency", "0", "/a"}},
		{"concurrency too high", []string{"--concurrency", "999", "/a"}},
		{"non-positive timeout", []string{"--timeout", "0s", "/a"}},
		{"unknown manager", []string{"--manager", "cargo", "/a"}},
		{"unknown severity", []string{"--fail-on", "spicy", "/a"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := Parse(c.args, io.Discard); err == nil {
				t.Fatalf("expected an error for %v", c.args)
			}
		})
	}
}

func TestParseAcceptsEverySeverity(t *testing.T) {
	for _, s := range []string{"low", "moderate", "high", "critical", "HIGH"} {
		cfg, err := Parse([]string{"--fail-on", s, "/a"}, io.Discard)
		if err != nil {
			t.Fatalf("--fail-on %s: %v", s, err)
		}
		if cfg.FailOn == model.SeverityUnknown {
			t.Errorf("--fail-on %s produced unknown", s)
		}
	}
}

func TestParseIgnoreIsRepeatableAndCommaSeparated(t *testing.T) {
	cfg, err := Parse([]string{"--ignore", "GHSA-a", "--ignore", "GHSA-b,1234", "/a"}, io.Discard)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	for _, want := range []string{"GHSA-a", "GHSA-b", "1234"} {
		if !cfg.Ignore[want] {
			t.Errorf("%q missing from the ignore set %v", want, cfg.Ignore)
		}
	}
}

func TestParseSelfActingFlagsNeedNoDirectory(t *testing.T) {
	for _, flag := range []string{"--help", "--version", "--list-cache", "--clean-cache"} {
		if _, err := Parse([]string{flag}, io.Discard); err != nil {
			t.Errorf("%s: %v", flag, err)
		}
	}
}

func TestParseCacheFlagsRejectADirectory(t *testing.T) {
	for _, flag := range []string{"--list-cache", "--clean-cache"} {
		if _, err := Parse([]string{flag, "/projects"}, io.Discard); err == nil {
			t.Errorf("%s with a directory should be rejected", flag)
		}
	}
	if _, err := Parse([]string{"--list-cache", "--clean-cache"}, io.Discard); err == nil {
		t.Error("--list-cache and --clean-cache together should be rejected")
	}
}

func TestHumanBytes(t *testing.T) {
	cases := map[int64]string{
		0:             "0 B",
		512:           "512 B",
		1024:          "1.0 KB",
		1536:          "1.5 KB",
		1024 * 1024:   "1.0 MB",
		235 * 1 << 20: "235.0 MB",
		3 * 1 << 30:   "3.0 GB",
	}
	for n, want := range cases {
		if got := humanBytes(n); got != want {
			t.Errorf("humanBytes(%d) = %q, want %q", n, got, want)
		}
	}
}

func TestUsageDocumentsWhatItPromises(t *testing.T) {
	var buf bytes.Buffer
	Usage(&buf)
	text := buf.String()

	for _, want := range []string{
		"USAGE", "EXIT CODES", "OUTPUT MODES", "SUPPORTED PACKAGE MANAGERS",
		"bun", "npm", "pnpm", "yarn",
		"not_checked", "--wanted", "--offline",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("help text is missing %q", want)
		}
	}
}

// report builds a minimal report for exit-code tests.
func report(projects ...*model.Project) *model.Report {
	r := &model.Report{Projects: projects}
	r.BuildSummary()
	return r
}

func cleanProject() *model.Project {
	p := &model.Project{Path: "/a", Name: "a"}
	p.Outdated = model.OutdatedResult{Status: model.StatusClean, Packages: []model.OutdatedPackage{}}
	p.Security = model.SecurityResult{Status: model.StatusClean, Packages: []model.VulnerablePackage{}}
	return p
}

func TestExitCodeClean(t *testing.T) {
	cfg := &Config{FailOn: model.SeverityLow}
	if got := ExitCode(report(cleanProject()), cfg); got != ExitOK {
		t.Fatalf("exit = %d, want 0", got)
	}
}

func TestExitCodeFindingsForVulnerability(t *testing.T) {
	p := cleanProject()
	p.Security = model.SecurityResult{
		Status: model.StatusFindings,
		Packages: []model.VulnerablePackage{
			{Name: "axios", MaxSeverity: model.SeverityModerate},
		},
	}

	cfg := &Config{FailOn: model.SeverityLow}
	if got := ExitCode(report(p), cfg); got != ExitFindings {
		t.Fatalf("exit = %d, want 1", got)
	}

	// A higher threshold lets the same finding pass.
	cfg = &Config{FailOn: model.SeverityCritical}
	if got := ExitCode(report(p), cfg); got != ExitOK {
		t.Fatalf("exit = %d with --fail-on critical, want 0", got)
	}
}

func TestExitCodeOutdatedDoesNotFailUnlessAsked(t *testing.T) {
	p := cleanProject()
	p.Outdated = model.OutdatedResult{
		Status:   model.StatusFindings,
		Packages: []model.OutdatedPackage{{Name: "vite", LatestUpdateType: model.UpdatePatch}},
	}

	cfg := &Config{FailOn: model.SeverityLow}
	if got := ExitCode(report(p), cfg); got != ExitOK {
		t.Fatalf("exit = %d, want 0: an available patch must not redden CI forever", got)
	}

	cfg.FailOnOutdated = true
	if got := ExitCode(report(p), cfg); got != ExitFindings {
		t.Fatalf("exit = %d with --fail-on-outdated, want 1", got)
	}
}

func TestExitCodeIncompleteWhenNothingFound(t *testing.T) {
	p := cleanProject()
	p.Security = model.SecurityResult{Status: model.StatusNotChecked, Packages: []model.VulnerablePackage{}}

	cfg := &Config{FailOn: model.SeverityLow}
	if got := ExitCode(report(p), cfg); got != ExitIncomplete {
		t.Fatalf("exit = %d, want 3: an unchecked axis is not a clean result", got)
	}
}

func TestExitCodeFindingsWinOverIncomplete(t *testing.T) {
	incomplete := cleanProject()
	incomplete.Security = model.SecurityResult{Status: model.StatusError, Packages: []model.VulnerablePackage{}}

	vulnerable := cleanProject()
	vulnerable.Path = "/b"
	vulnerable.Security = model.SecurityResult{
		Status:   model.StatusFindings,
		Packages: []model.VulnerablePackage{{Name: "axios", MaxSeverity: model.SeverityHigh}},
	}

	cfg := &Config{FailOn: model.SeverityLow}
	if got := ExitCode(report(incomplete, vulnerable), cfg); got != ExitFindings {
		t.Fatalf("exit = %d, want 1: precedence is 1 over 3", got)
	}
}

func TestRunOfflineOverFixturesProducesHonestJSON(t *testing.T) {
	cfg, err := Parse([]string{
		"--json", "--offline", "--no-cache",
		"../../testdata/fixtures",
	}, io.Discard)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := Run(cfg, &stdout, &stderr)

	var rep model.Report
	if err := json.Unmarshal(stdout.Bytes(), &rep); err != nil {
		t.Fatalf("stdout is not a single JSON document: %v\n%s", err, stdout.String())
	}
	if !rep.Options.Offline {
		t.Error("options.offline must record how the scan ran")
	}
	if rep.DepscanVersion != Version {
		t.Errorf("version = %q", rep.DepscanVersion)
	}
	if len(rep.Projects) < 10 {
		t.Fatalf("found %d projects in the fixture tree, want at least 10", len(rep.Projects))
	}

	// Offline with an empty cache can answer nothing, and must say so rather than
	// reporting clean results.
	for _, p := range rep.Projects {
		if p.Outdated.Status == model.StatusClean || p.Security.Status == model.StatusClean {
			t.Errorf("%s reported clean while offline with no cache: %q / %q",
				p.Name, p.Outdated.Status, p.Security.Status)
		}
		if p.Outdated.Packages == nil || p.Security.Packages == nil || p.Errors == nil {
			t.Errorf("%s has a null collection; every list must serialize as []", p.Name)
		}
	}
	if rep.Summary.FullyAnalyzed != 0 {
		t.Errorf("fullyAnalyzed = %d, want 0", rep.Summary.FullyAnalyzed)
	}
	if rep.Summary.Projects != len(rep.Projects) {
		t.Errorf("summary.projects = %d, want %d", rep.Summary.Projects, len(rep.Projects))
	}
	if code != ExitIncomplete {
		t.Errorf("exit = %d, want 3: nothing was found but nothing was verified either", code)
	}
}

func TestRunRejectsAMissingRoot(t *testing.T) {
	cfg, err := Parse([]string{"--quiet", "./definitely-not-here"}, io.Discard)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	var stdout, stderr bytes.Buffer
	if code := Run(cfg, &stdout, &stderr); code != ExitOperational {
		t.Fatalf("exit = %d, want 2", code)
	}
	if stderr.Len() == 0 {
		t.Error("the failure must be explained on stderr")
	}
}

func TestRunManagerFilter(t *testing.T) {
	cfg, err := Parse([]string{
		"--json", "--offline", "--no-cache", "--manager", "pnpm",
		"../../testdata/fixtures",
	}, io.Discard)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	var stdout, stderr bytes.Buffer
	Run(cfg, &stdout, &stderr)

	var rep model.Report
	if err := json.Unmarshal(stdout.Bytes(), &rep); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(rep.Projects) == 0 {
		t.Fatal("expected the pnpm fixtures")
	}
	for _, p := range rep.Projects {
		if p.PackageManager != "pnpm" {
			t.Errorf("%s has manager %q, want only pnpm", p.Name, p.PackageManager)
		}
	}
}
