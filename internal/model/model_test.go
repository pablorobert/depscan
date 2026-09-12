package model

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestSeverityOrdering(t *testing.T) {
	if !SeverityCritical.AtLeast(SeverityHigh) {
		t.Error("critical is at least high")
	}
	if SeverityLow.AtLeast(SeverityModerate) {
		t.Error("low is not at least moderate")
	}
	if !SeverityLow.AtLeast(SeverityLow) {
		t.Error("a severity is at least itself")
	}
	if SeverityUnknown.AtLeast(SeverityLow) {
		t.Error("unknown must not satisfy a low threshold")
	}
	if got := MaxSeverity(SeverityModerate, SeverityCritical); got != SeverityCritical {
		t.Errorf("MaxSeverity = %q", got)
	}
	if got := MaxSeverity(SeverityHigh, SeverityLow); got != SeverityHigh {
		t.Errorf("MaxSeverity = %q", got)
	}
}

func TestParseSeverityDoesNotInvent(t *testing.T) {
	for _, in := range []string{"critical", "high", "moderate", "low"} {
		if got := ParseSeverity(in); string(got) != in {
			t.Errorf("ParseSeverity(%q) = %q", in, got)
		}
	}
	for _, in := range []string{"", "catastrophic", "HIGH", "info"} {
		if got := ParseSeverity(in); got != SeverityUnknown {
			t.Errorf("ParseSeverity(%q) = %q, want unknown", in, got)
		}
	}
}

func TestFullyAnalyzedRequiresBothAxesVerified(t *testing.T) {
	cases := []struct {
		outdated, security Status
		want               bool
	}{
		{StatusClean, StatusClean, true},
		{StatusFindings, StatusClean, true},
		{StatusFindings, StatusFindings, true},
		{StatusClean, StatusNotChecked, false},
		{StatusNotChecked, StatusClean, false},
		{StatusClean, StatusError, false},
		{StatusError, StatusError, false},
	}
	for _, c := range cases {
		p := &Project{}
		p.Outdated.Status = c.outdated
		p.Security.Status = c.security
		if got := p.FullyAnalyzed(); got != c.want {
			t.Errorf("FullyAnalyzed(%q, %q) = %v, want %v", c.outdated, c.security, got, c.want)
		}
		if p.Incomplete() == c.want {
			t.Errorf("Incomplete must be the inverse of FullyAnalyzed for (%q, %q)", c.outdated, c.security)
		}
	}
}

func TestBuildSummaryCountsAffectedPackagesNotAdvisories(t *testing.T) {
	p := &Project{}
	p.Outdated.Status = StatusFindings
	p.Outdated.Packages = []OutdatedPackage{
		{Name: "a", LatestUpdateType: UpdatePatch},
		{Name: "b", LatestUpdateType: UpdateMajor},
	}
	p.Security.Status = StatusFindings
	p.Security.Packages = []VulnerablePackage{
		{Name: "axios", MaxSeverity: SeverityHigh, Advisories: make([]Advisory, 29)},
		{Name: "vite", MaxSeverity: SeverityModerate, Advisories: make([]Advisory, 17)},
	}

	r := &Report{Projects: []*Project{p}}
	r.BuildSummary()

	if r.Summary.VulnerablePackages != 2 {
		t.Errorf("vulnerablePackages = %d, want 2", r.Summary.VulnerablePackages)
	}
	if r.Summary.Advisories != 46 {
		t.Errorf("advisories = %d, want 46", r.Summary.Advisories)
	}
	if r.Summary.BySeverity.High != 1 || r.Summary.BySeverity.Moderate != 1 {
		t.Errorf("bySeverity = %+v", r.Summary.BySeverity)
	}
	if r.Summary.OutdatedPackages != 2 {
		t.Errorf("outdatedPackages = %d, want 2", r.Summary.OutdatedPackages)
	}
	if r.Summary.ByUpdateType.Patch != 1 || r.Summary.ByUpdateType.Major != 1 {
		t.Errorf("byUpdateType = %+v", r.Summary.ByUpdateType)
	}
	if r.Summary.FullyAnalyzed != 1 {
		t.Errorf("fullyAnalyzed = %d, want 1", r.Summary.FullyAnalyzed)
	}
}

func TestBuildSummaryCountsIncompleteProjects(t *testing.T) {
	notChecked := &Project{Path: "/a"}
	notChecked.Outdated.Status = StatusClean
	notChecked.Security.Status = StatusNotChecked

	failed := &Project{Path: "/b"}
	failed.Outdated.Status = StatusError
	failed.Security.Status = StatusError
	failed.AddError(ErrNoLockfile, PhaseLockfile, "no lockfile")

	r := &Report{Projects: []*Project{notChecked, failed}}
	r.BuildSummary()

	if r.Summary.ProjectsNotChecked != 1 {
		t.Errorf("projectsNotChecked = %d, want 1", r.Summary.ProjectsNotChecked)
	}
	if r.Summary.ProjectsWithErrors != 1 {
		t.Errorf("projectsWithErrors = %d, want 1", r.Summary.ProjectsWithErrors)
	}
	if r.Summary.FullyAnalyzed != 0 {
		t.Errorf("fullyAnalyzed = %d, want 0", r.Summary.FullyAnalyzed)
	}
	if !r.AnyIncomplete() {
		t.Error("AnyIncomplete must be true")
	}
}

func TestHasFindingsAtLeast(t *testing.T) {
	p := &Project{}
	p.Security.Packages = []VulnerablePackage{{Name: "x", MaxSeverity: SeverityModerate}}
	r := &Report{Projects: []*Project{p}}

	if !r.HasFindingsAtLeast(SeverityLow) {
		t.Error("a moderate finding clears a low threshold")
	}
	if r.HasFindingsAtLeast(SeverityHigh) {
		t.Error("a moderate finding must not clear a high threshold")
	}
}

func TestCategoryOrNilKeepsTransitiveNull(t *testing.T) {
	if got := (Dep{Category: CategoryDev}).CategoryOrNil(); got == nil || *got != CategoryDev {
		t.Fatalf("CategoryOrNil = %v", got)
	}
	if got := (Dep{}).CategoryOrNil(); got != nil {
		t.Fatalf("a transitive dependency must serialize a null category, got %q", *got)
	}
}

func TestJSONFieldNamesMatchTheDocumentedSchema(t *testing.T) {
	wanted := "1.18.0"
	fixed := "1.8.2"
	vector := "CVSS:3.1/AV:N"
	category := CategoryProd

	r := Report{
		Root:           "/projects",
		DepscanVersion: "0.1.0",
		StartedAt:      "2026-09-12T00:00:00Z",
		Options:        Options{Cache: true},
		Projects: []*Project{{
			Path: "/projects/app",
			Name: "app",
			Outdated: OutdatedResult{
				Status: StatusFindings,
				Packages: []OutdatedPackage{{
					Name: "axios", Declared: "^1.6.0", Current: "1.6.0",
					Wanted: &wanted, Latest: "1.20.0",
					UpdateType: UpdateMinor, LatestUpdateType: UpdateMajor,
					WantedSource: WantedRegistry, Direct: true, Category: &category,
				}},
			},
			Security: SecurityResult{
				Status: StatusFindings,
				Packages: []VulnerablePackage{{
					Name: "axios", InstalledVersion: "1.6.0", MaxSeverity: SeverityHigh,
					Direct: true, Category: &category,
					FixedVersion: &fixed, FixedInferred: true,
					Advisories: []Advisory{{
						ID: 1, URL: "https://x", Title: "t", Severity: SeverityHigh,
						VulnerableVersions: ">=1.0.0 <1.8.2", CWE: []string{"CWE-918"},
						CVSS: CVSS{Score: 7.5, VectorString: &vector},
					}},
				}},
			},
			Errors: []ProjectError{},
		}},
	}
	r.BuildSummary()

	data, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	text := string(data)

	for _, want := range []string{
		`"depscanVersion"`, `"startedAt"`, `"durationMs"`,
		`"packageManager"`, `"workspaceRoot"`, `"lockfile"`,
		`"wantedSource":"registry"`, `"latestUpdateType":"major"`, `"updateType":"minor"`,
		`"declared":"^1.6.0"`, `"current":"1.6.0"`, `"wanted":"1.18.0"`, `"latest":"1.20.0"`,
		`"installedVersion"`, `"maxSeverity":"high"`, `"fixedVersionInferred":true`,
		`"vulnerableVersions"`, `"vectorString"`,
		`"vulnerablePackages":1`, `"advisories":1`, `"bySeverity"`, `"byUpdateType"`,
		`"projectsNotChecked":0`, `"projectsWithErrors":0`, `"fullyAnalyzed":1`,
		`"status":"findings"`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("JSON is missing %s", want)
		}
	}
}

func TestNullableFieldsSerializeAsNull(t *testing.T) {
	p := &Project{
		Outdated: OutdatedResult{
			Status:   StatusFindings,
			Packages: []OutdatedPackage{{Name: "react", WantedSource: WantedNotComputed}},
		},
		Security: SecurityResult{Status: StatusClean, Packages: []VulnerablePackage{}},
		Errors:   []ProjectError{},
	}

	data, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	text := string(data)

	for _, want := range []string{
		`"wanted":null`, `"category":null`, `"workspaceRoot":null`,
		`"wantedSource":"not-computed"`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("JSON is missing %s\n%s", want, text)
		}
	}
	if strings.Contains(text, `"packages":null`) {
		t.Error("an empty package list must serialize as [], never null")
	}
}
