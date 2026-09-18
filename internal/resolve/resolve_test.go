package resolve

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pablorobert/depscan/internal/advisory"
	"github.com/pablorobert/depscan/internal/model"
	"github.com/pablorobert/depscan/internal/registry"
)

// fakeRegistry serves dist-tags, packuments and the bulk advisory endpoint from
// in-memory tables, so no test touches the network.
type fakeRegistry struct {
	latest     map[string]string
	versions   map[string][]string
	advisories map[string]string // package -> raw JSON array
	// published serves the full packument: package -> version -> RFC 3339 time.
	published  map[string]map[string]string
	distTagHit atomic.Int32
	packumHit  atomic.Int32
	fullHit    atomic.Int32
	bulkHit    atomic.Int32
	bulkStatus int
}

func (f *fakeRegistry) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/security/advisories/bulk"):
			f.bulkHit.Add(1)
			if f.bulkStatus != 0 {
				w.WriteHeader(f.bulkStatus)
				return
			}
			var req map[string][]string
			_ = json.NewDecoder(r.Body).Decode(&req)

			parts := make([]string, 0, len(req))
			for name := range req {
				if raw, ok := f.advisories[name]; ok {
					parts = append(parts, fmt.Sprintf("%q:%s", name, raw))
				}
			}
			fmt.Fprintf(w, "{%s}", strings.Join(parts, ","))

		case strings.HasSuffix(r.URL.Path, "/dist-tags"):
			f.distTagHit.Add(1)
			name := strings.TrimSuffix(strings.TrimPrefix(r.URL.EscapedPath(), "/-/package/"), "/dist-tags")
			name = strings.ReplaceAll(name, "%2F", "/")
			v, ok := f.latest[name]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			fmt.Fprintf(w, `{"latest":%q}`, v)

		case r.Header.Get("Accept") == "application/json":
			f.fullHit.Add(1)
			name := strings.ReplaceAll(strings.TrimPrefix(r.URL.EscapedPath(), "/"), "%2F", "/")
			times, ok := f.published[name]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			versions := make([]string, 0, len(times))
			stamps := make([]string, 0, len(times))
			for v, ts := range times {
				versions = append(versions, fmt.Sprintf("%q:{}", v))
				stamps = append(stamps, fmt.Sprintf("%q:%q", v, ts))
			}
			fmt.Fprintf(w, `{"versions":{%s},"time":{"created":"2020-01-01T00:00:00Z",%s}}`,
				strings.Join(versions, ","), strings.Join(stamps, ","))

		default:
			f.packumHit.Add(1)
			name := strings.ReplaceAll(strings.TrimPrefix(r.URL.EscapedPath(), "/"), "%2F", "/")
			vs, ok := f.versions[name]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			entries := make([]string, 0, len(vs))
			for _, v := range vs {
				entries = append(entries, fmt.Sprintf("%q:{}", v))
			}
			fmt.Fprintf(w, `{"versions":{%s}}`, strings.Join(entries, ","))
		}
	})
}

func (f *fakeRegistry) clients(t *testing.T) Clients {
	t.Helper()
	srv := httptest.NewServer(f.handler())
	t.Cleanup(srv.Close)
	return Clients{
		Registry: registry.New(registry.Options{BaseURL: srv.URL, Concurrency: 4, Timeout: 2 * time.Second}),
		Advisory: advisory.New(advisory.Options{BaseURL: srv.URL, Timeout: 2 * time.Second}),
	}
}

func projectWith(name string, deps ...model.Dep) *model.Project {
	return &model.Project{Path: "/tmp/" + name, Name: name, PackageManager: "bun", Deps: deps}
}

func directDep(name, declared, version string) model.Dep {
	return model.Dep{
		Name: name, Declared: declared, Version: version,
		Direct: true, Category: model.CategoryProd,
	}
}

func outdatedFor(p *model.Project, name string) (model.OutdatedPackage, bool) {
	for _, o := range p.Outdated.Packages {
		if o.Name == name {
			return o, true
		}
	}
	return model.OutdatedPackage{}, false
}

func TestWantedEqualsLatestNeedsNoPackument(t *testing.T) {
	f := &fakeRegistry{latest: map[string]string{"axios": "1.20.0"}}
	p := projectWith("app", directDep("axios", "^1.6.0", "1.6.0"))

	Run(context.Background(), []*model.Project{p}, f.clients(t), Options{})

	o, ok := outdatedFor(p, "axios")
	if !ok {
		t.Fatal("axios should be reported as outdated")
	}
	if o.WantedSource != model.WantedEqualsLatest {
		t.Fatalf("wantedSource = %q, want equals-latest", o.WantedSource)
	}
	if o.Wanted == nil || *o.Wanted != "1.20.0" {
		t.Fatalf("wanted = %v, want 1.20.0", o.Wanted)
	}
	if o.UpdateType != model.UpdateMinor || o.LatestUpdateType != model.UpdateMinor {
		t.Fatalf("updateType = %q / %q, want minor / minor", o.UpdateType, o.LatestUpdateType)
	}
	if got := f.packumHit.Load(); got != 0 {
		t.Fatalf("packument requests = %d, want 0: the range accepts latest, so wanted is proven locally", got)
	}
}

func TestWantedNotComputedWithoutTheFlag(t *testing.T) {
	f := &fakeRegistry{latest: map[string]string{"react": "19.2.0"}}
	p := projectWith("app", directDep("react", "^18.0.0", "18.2.0"))

	Run(context.Background(), []*model.Project{p}, f.clients(t), Options{Wanted: false})

	o, _ := outdatedFor(p, "react")
	if o.WantedSource != model.WantedNotComputed {
		t.Fatalf("wantedSource = %q, want not-computed", o.WantedSource)
	}
	if o.Wanted != nil {
		t.Fatalf("wanted = %v, want nil: claiming a value we did not compute is forbidden", *o.Wanted)
	}
	if o.UpdateType != model.UpdateUnknown {
		t.Fatalf("updateType = %q, want unknown", o.UpdateType)
	}
	if o.LatestUpdateType != model.UpdateMajor {
		t.Fatalf("latestUpdateType = %q, want major", o.LatestUpdateType)
	}
	if got := f.packumHit.Load(); got != 0 {
		t.Fatalf("packument requests = %d, want 0 without --wanted", got)
	}
}

func TestWantedFlagFetchesPackumentAndComputesInRangeMaximum(t *testing.T) {
	f := &fakeRegistry{
		latest:   map[string]string{"react": "19.2.0"},
		versions: map[string][]string{"react": {"18.2.0", "18.3.1", "19.0.0", "19.2.0"}},
	}
	p := projectWith("app", directDep("react", "^18.0.0", "18.2.0"))

	Run(context.Background(), []*model.Project{p}, f.clients(t), Options{Wanted: true})

	o, _ := outdatedFor(p, "react")
	if o.WantedSource != model.WantedRegistry {
		t.Fatalf("wantedSource = %q, want registry", o.WantedSource)
	}
	if o.Wanted == nil || *o.Wanted != "18.3.1" {
		t.Fatalf("wanted = %v, want 18.3.1", o.Wanted)
	}
	if o.UpdateType != model.UpdateMinor {
		t.Fatalf("updateType = %q, want minor (current -> wanted)", o.UpdateType)
	}
	if o.LatestUpdateType != model.UpdateMajor {
		t.Fatalf("latestUpdateType = %q, want major (current -> latest)", o.LatestUpdateType)
	}
	if got := f.packumHit.Load(); got != 1 {
		t.Fatalf("packument requests = %d, want exactly 1", got)
	}
}

// releaseAgeNow is the reference clock for the minimum release age tests; with a 72h
// window, anything published after 2026-09-15T12:00Z is held back.
var releaseAgeNow = time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC)

func withWindow(p *model.Project, excludes ...string) *model.Project {
	p.MinimumReleaseAge = &model.MinimumReleaseAge{Seconds: 259200, Excludes: excludes, Source: "bunfig.toml"}
	return p
}

func TestReleaseAgeHoldsBackRecentLatest(t *testing.T) {
	// Shape of @babel/core in a real scan: 8.0.6 is two days old, 8.0.5 is not.
	f := &fakeRegistry{
		latest: map[string]string{"@babel/core": "8.0.6"},
		published: map[string]map[string]string{"@babel/core": {
			"7.29.7":       "2026-06-01T00:00:00Z",
			"7.29.8":       "2026-09-17T00:00:00Z",
			"8.0.5":        "2026-09-10T00:00:00Z",
			"8.1.0-beta.1": "2026-09-11T00:00:00Z",
			"8.0.6":        "2026-09-16T12:00:00Z",
		}},
	}
	p := withWindow(projectWith("app", directDep("@babel/core", "^7.29.0", "7.29.7")))

	Run(context.Background(), []*model.Project{p}, f.clients(t), Options{Now: releaseAgeNow})

	o, ok := outdatedFor(p, "@babel/core")
	if !ok || o.ReleaseAge == nil {
		t.Fatalf("release age missing: %+v", o)
	}
	if o.ReleaseAge.Status != model.ReleaseAgeHeldBack {
		t.Fatalf("status = %q, want held-back", o.ReleaseAge.Status)
	}
	if o.ReleaseAge.Eligible == nil || *o.ReleaseAge.Eligible != "8.0.5" {
		t.Fatalf("eligible = %v, want 8.0.5 (the prerelease and the too-recent 8.0.6 skipped)", o.ReleaseAge.Eligible)
	}
	if o.ReleaseAge.LatestPublishedAt == nil || *o.ReleaseAge.LatestPublishedAt != "2026-09-16T12:00:00Z" {
		t.Fatalf("latestPublishedAt = %v", o.ReleaseAge.LatestPublishedAt)
	}
	if o.Latest != "8.0.6" {
		t.Fatalf("latest = %q: the registry's latest is still reported as is", o.Latest)
	}
	// 7.29.8 is in range but too recent, so bun update would stay on 7.29.7.
	if o.Wanted == nil || *o.Wanted != "7.29.7" || o.WantedSource != model.WantedRegistry {
		t.Fatalf("wanted = %v (%s), want 7.29.7 from the registry", o.Wanted, o.WantedSource)
	}
	if o.UpdateType != model.UpdateNone {
		t.Fatalf("updateType = %q, want none", o.UpdateType)
	}
}

func TestReleaseAgePassedComputesWantedForFree(t *testing.T) {
	f := &fakeRegistry{
		latest: map[string]string{"react": "19.2.0"},
		published: map[string]map[string]string{"react": {
			"18.2.0": "2024-01-01T00:00:00Z",
			"18.3.1": "2024-04-26T00:00:00Z",
			"19.2.0": "2026-01-01T00:00:00Z",
		}},
	}
	p := withWindow(projectWith("app", directDep("react", "^18.0.0", "18.2.0")))

	Run(context.Background(), []*model.Project{p}, f.clients(t), Options{Now: releaseAgeNow})

	o, _ := outdatedFor(p, "react")
	if o.ReleaseAge == nil || o.ReleaseAge.Status != model.ReleaseAgePassed {
		t.Fatalf("release age = %+v, want passed", o.ReleaseAge)
	}
	if o.ReleaseAge.Eligible == nil || *o.ReleaseAge.Eligible != "19.2.0" {
		t.Fatalf("eligible = %v, want latest", o.ReleaseAge.Eligible)
	}
	// The full version list was fetched anyway, so wanted needs no --wanted.
	if o.Wanted == nil || *o.Wanted != "18.3.1" || o.WantedSource != model.WantedRegistry {
		t.Fatalf("wanted = %v (%s), want 18.3.1 from the registry", o.Wanted, o.WantedSource)
	}
	if got := f.packumHit.Load(); got != 0 {
		t.Fatalf("abbreviated packument requests = %d, want 0", got)
	}
}

func TestReleaseAgeExcludedPackageIsNotFetched(t *testing.T) {
	f := &fakeRegistry{latest: map[string]string{"axios": "1.20.0"}}
	p := withWindow(projectWith("app", directDep("axios", "^1.6.0", "1.6.0")), "axios")

	Run(context.Background(), []*model.Project{p}, f.clients(t), Options{Now: releaseAgeNow})

	o, _ := outdatedFor(p, "axios")
	if o.ReleaseAge == nil || o.ReleaseAge.Status != model.ReleaseAgeExcluded {
		t.Fatalf("release age = %+v, want excluded", o.ReleaseAge)
	}
	if got := f.fullHit.Load(); got != 0 {
		t.Fatalf("full packument requests = %d, want 0 for an excluded package", got)
	}
}

func TestReleaseAgeFetchFailureIsNotCheckedAndReported(t *testing.T) {
	f := &fakeRegistry{latest: map[string]string{"axios": "1.20.0"}}
	p := withWindow(projectWith("app", directDep("axios", "^1.6.0", "1.6.0")))

	Run(context.Background(), []*model.Project{p}, f.clients(t), Options{Now: releaseAgeNow})

	o, _ := outdatedFor(p, "axios")
	if o.ReleaseAge == nil || o.ReleaseAge.Status != model.ReleaseAgeNotChecked {
		t.Fatalf("release age = %+v, want not-checked", o.ReleaseAge)
	}
	if len(p.Errors) == 0 {
		t.Fatal("the failed lookup must be recorded on the project")
	}
}

func TestNoWindowMeansNoFullPackument(t *testing.T) {
	f := &fakeRegistry{latest: map[string]string{"axios": "1.20.0"}}
	p := projectWith("app", directDep("axios", "^1.6.0", "1.6.0"))

	Run(context.Background(), []*model.Project{p}, f.clients(t), Options{Now: releaseAgeNow})

	o, _ := outdatedFor(p, "axios")
	if o.ReleaseAge != nil {
		t.Fatalf("release age = %+v, want nil without a window", o.ReleaseAge)
	}
	if got := f.fullHit.Load(); got != 0 {
		t.Fatalf("full packument requests = %d, want 0", got)
	}
}

func TestUpToDateProjectIsClean(t *testing.T) {
	f := &fakeRegistry{latest: map[string]string{"axios": "1.6.0"}}
	p := projectWith("app", directDep("axios", "^1.6.0", "1.6.0"))

	Run(context.Background(), []*model.Project{p}, f.clients(t), Options{})

	if p.Outdated.Status != model.StatusClean {
		t.Fatalf("outdated status = %q, want clean", p.Outdated.Status)
	}
	if p.Security.Status != model.StatusClean {
		t.Fatalf("security status = %q, want clean", p.Security.Status)
	}
	if len(p.Outdated.Packages) != 0 {
		t.Fatalf("packages = %v, want empty", p.Outdated.Packages)
	}
}

func TestNetworkFailureOnAllDepsIsErrorNotClean(t *testing.T) {
	// The fake knows no packages, so every dist-tags lookup 404s.
	f := &fakeRegistry{latest: map[string]string{}}
	p := projectWith("app", directDep("axios", "^1.6.0", "1.6.0"))

	Run(context.Background(), []*model.Project{p}, f.clients(t), Options{})

	if p.Outdated.Status != model.StatusError {
		t.Fatalf("outdated status = %q, want error — an unreachable registry is never 'up to date'", p.Outdated.Status)
	}
	if len(p.Errors) == 0 {
		t.Fatal("the failure must be recorded on the project")
	}
	if p.Errors[0].Phase != model.PhaseOutdated {
		t.Fatalf("phase = %q, want outdated", p.Errors[0].Phase)
	}
}

func TestAdvisoryFailureMarksEveryProjectAsError(t *testing.T) {
	f := &fakeRegistry{
		latest:     map[string]string{"axios": "1.6.0"},
		bulkStatus: http.StatusInternalServerError,
	}
	a := projectWith("a", directDep("axios", "^1.6.0", "1.6.0"))
	b := projectWith("b", directDep("axios", "^1.6.0", "1.6.0"))

	Run(context.Background(), []*model.Project{a, b}, f.clients(t), Options{})

	for _, p := range []*model.Project{a, b} {
		if p.Security.Status != model.StatusError {
			t.Errorf("%s security status = %q, want error", p.Name, p.Security.Status)
		}
		if p.Outdated.Status != model.StatusClean {
			t.Errorf("%s outdated status = %q: a security failure must not poison the other axis", p.Name, p.Outdated.Status)
		}
		if p.Incomplete() != true {
			t.Errorf("%s should count as incomplete", p.Name)
		}
	}
}

func TestOnlyOutdatedLeavesSecurityNotChecked(t *testing.T) {
	f := &fakeRegistry{latest: map[string]string{"axios": "1.6.0"}}
	p := projectWith("app", directDep("axios", "^1.6.0", "1.6.0"))

	Run(context.Background(), []*model.Project{p}, f.clients(t), Options{SkipVulnerable: true})

	if p.Security.Status != model.StatusNotChecked {
		t.Fatalf("security status = %q, want not_checked — never clean", p.Security.Status)
	}
	if got := f.bulkHit.Load(); got != 0 {
		t.Fatalf("bulk requests = %d, want 0", got)
	}
	if p.FullyAnalyzed() {
		t.Fatal("a project with a skipped axis is not fully analyzed")
	}
}

func TestOnlyVulnerableLeavesOutdatedNotChecked(t *testing.T) {
	f := &fakeRegistry{latest: map[string]string{"axios": "1.20.0"}}
	p := projectWith("app", directDep("axios", "^1.6.0", "1.6.0"))

	Run(context.Background(), []*model.Project{p}, f.clients(t), Options{SkipOutdated: true})

	if p.Outdated.Status != model.StatusNotChecked {
		t.Fatalf("outdated status = %q, want not_checked", p.Outdated.Status)
	}
	if got := f.distTagHit.Load(); got != 0 {
		t.Fatalf("dist-tags requests = %d, want 0", got)
	}
}

func TestSecurityCoversTransitivesAndMarksDirectness(t *testing.T) {
	f := &fakeRegistry{
		latest: map[string]string{"vite": "5.0.0"},
		advisories: map[string]string{
			"vite":    `[{"id":1,"severity":"high","vulnerable_versions":">=5.0.0 <5.4.0","url":"https://github.com/advisories/GHSA-aaaa-bbbb-cccc"}]`,
			"esbuild": `[{"id":2,"severity":"moderate","vulnerable_versions":"<=0.24.2","url":"https://github.com/advisories/GHSA-dddd-eeee-ffff"}]`,
		},
	}
	p := projectWith("app",
		model.Dep{Name: "vite", Declared: "^5.0.0", Version: "5.0.0", Direct: true, Category: model.CategoryDev},
		model.Dep{Name: "esbuild", Version: "0.21.5"},
	)

	Run(context.Background(), []*model.Project{p}, f.clients(t), Options{})

	if p.Security.Status != model.StatusFindings {
		t.Fatalf("security status = %q, want findings", p.Security.Status)
	}
	if len(p.Security.Packages) != 2 {
		t.Fatalf("affected packages = %d, want 2 (the transitive one must not be hidden)", len(p.Security.Packages))
	}

	// Direct findings sort first.
	first := p.Security.Packages[0]
	if first.Name != "vite" || !first.Direct {
		t.Fatalf("first entry = %+v, want the direct vite finding", first)
	}
	if *first.Category != model.CategoryDev {
		t.Fatalf("vite category = %q, want devDependency", *first.Category)
	}
	if first.FixedVersion == nil || *first.FixedVersion != "5.4.0" {
		t.Fatalf("vite fixedVersion = %v, want 5.4.0 inferred", first.FixedVersion)
	}
	if !first.FixedInferred {
		t.Error("fixedVersionInferred must be true: the value is derived, not reported by the registry")
	}

	second := p.Security.Packages[1]
	if second.Name != "esbuild" || second.Direct {
		t.Fatalf("second entry = %+v, want the transitive esbuild finding", second)
	}
	if second.Category != nil {
		t.Error("a transitive dependency has no category")
	}
	if second.FixedVersion != nil {
		t.Errorf("an inclusive upper bound gives no fix; got %q", *second.FixedVersion)
	}
}

func TestAdvisoriesAreRecheckedAgainstEachProjectVersion(t *testing.T) {
	// One bulk response covers the union of versions across projects, so the
	// per-project match has to be redone locally.
	f := &fakeRegistry{
		latest: map[string]string{"axios": "1.20.0"},
		advisories: map[string]string{
			"axios": `[{"id":1,"severity":"high","vulnerable_versions":">=1.0.0 <1.8.2","url":"https://x/GHSA-1"}]`,
		},
	}
	vulnerable := projectWith("old", directDep("axios", "^1.6.0", "1.6.0"))
	safe := projectWith("new", directDep("axios", "^1.20.0", "1.20.0"))

	Run(context.Background(), []*model.Project{vulnerable, safe}, f.clients(t), Options{})

	if vulnerable.Security.Status != model.StatusFindings {
		t.Errorf("old project status = %q, want findings", vulnerable.Security.Status)
	}
	if safe.Security.Status != model.StatusClean {
		t.Errorf("new project status = %q, want clean: 1.20.0 is outside the vulnerable range",
			safe.Security.Status)
	}
	if len(safe.Security.Packages) != 0 {
		t.Errorf("new project findings = %v, want none", safe.Security.Packages)
	}
}

func TestIgnoreDropsAdvisoryByGHSAAndByID(t *testing.T) {
	advisories := map[string]string{
		"axios": `[{"id":1111035,"severity":"high","vulnerable_versions":">=1.0.0 <1.8.2","url":"https://github.com/advisories/GHSA-jr5f-v2jv-69x6"}]`,
	}

	for _, ignore := range []string{"GHSA-jr5f-v2jv-69x6", "1111035"} {
		f := &fakeRegistry{latest: map[string]string{"axios": "1.6.0"}, advisories: advisories}
		p := projectWith("app", directDep("axios", "^1.6.0", "1.6.0"))

		Run(context.Background(), []*model.Project{p}, f.clients(t), Options{
			Ignore: map[string]bool{ignore: true},
		})

		if p.Security.Status != model.StatusClean {
			t.Errorf("ignoring %q: status = %q, want clean", ignore, p.Security.Status)
		}
	}
}

func TestNonRegistryRangesAreSkippedSilently(t *testing.T) {
	f := &fakeRegistry{latest: map[string]string{}}
	p := projectWith("app",
		model.Dep{Name: "sibling", Declared: "workspace:*", Version: "", Direct: true, Category: model.CategoryProd},
		model.Dep{Name: "vendored", Declared: "file:../vendored", Version: "", Direct: true, Category: model.CategoryProd},
	)

	Run(context.Background(), []*model.Project{p}, f.clients(t), Options{})

	if p.Outdated.Status != model.StatusClean {
		t.Fatalf("status = %q, want clean: a workspace link has no registry counterpart", p.Outdated.Status)
	}
	if len(p.Errors) != 0 {
		t.Fatalf("errors = %v, want none", p.Errors)
	}
	if got := f.distTagHit.Load(); got != 0 {
		t.Fatalf("dist-tags requests = %d, want 0", got)
	}
}

func TestDeclaredButUnresolvedDependencyIsReportedAsAnError(t *testing.T) {
	f := &fakeRegistry{latest: map[string]string{"ghost": "1.0.0"}}
	p := projectWith("app", directDep("ghost", "^1.0.0", ""))

	Run(context.Background(), []*model.Project{p}, f.clients(t), Options{})

	if p.Outdated.Status != model.StatusError {
		t.Fatalf("status = %q, want error", p.Outdated.Status)
	}
	found := false
	for _, e := range p.Errors {
		if e.Kind == model.ErrParseLockfile {
			found = true
		}
	}
	if !found {
		t.Fatalf("errors = %+v, want a parse_lockfile entry", p.Errors)
	}
}

func TestNetworkWorkIsDedupedAcrossProjects(t *testing.T) {
	f := &fakeRegistry{latest: map[string]string{"axios": "1.20.0", "react": "19.2.0"}}

	var projects []*model.Project
	for i := range 25 {
		projects = append(projects, projectWith(fmt.Sprintf("app-%d", i),
			directDep("axios", "^1.6.0", "1.6.0"),
			directDep("react", "^18.0.0", "18.2.0"),
		))
	}

	Run(context.Background(), projects, f.clients(t), Options{})

	// Two unique names across 25 projects: two dist-tags requests, one bulk POST.
	if got := f.distTagHit.Load(); got != 2 {
		t.Errorf("dist-tags requests = %d, want 2 for 25 projects sharing two packages", got)
	}
	if got := f.bulkHit.Load(); got != 1 {
		t.Errorf("bulk requests = %d, want 1", got)
	}
}

func TestAlreadyFailedProjectIsLeftAloneAndNormalized(t *testing.T) {
	f := &fakeRegistry{latest: map[string]string{}}
	broken := &model.Project{Path: "/tmp/broken", Name: "broken"}
	broken.Outdated.Status = model.StatusError
	broken.Security.Status = model.StatusError
	broken.AddError(model.ErrParsePackageJSON, model.PhaseDiscovery, "package.json could not be parsed")

	Run(context.Background(), []*model.Project{broken}, f.clients(t), Options{})

	if broken.Outdated.Status != model.StatusError || broken.Security.Status != model.StatusError {
		t.Fatal("a project that failed earlier must keep its error status")
	}
	if broken.Outdated.Packages == nil || broken.Security.Packages == nil {
		t.Fatal("collections must be non-nil so JSON never emits null in place of a list")
	}
	if got := f.bulkHit.Load(); got != 0 {
		t.Fatalf("bulk requests = %d, want 0: there was nothing to ask about", got)
	}
}
