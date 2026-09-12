// Package resolve runs phase 2 and phase 3 of a scan: batching the network work by
// unique package and joining the answers back onto each project.
//
// The batching is what makes the scan fast. 100 projects share most of their
// dependencies, so the network is addressed per unique package, never per project.
// SPEC.md section 5.
package resolve

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/pablorobert/depscan/internal/advisory"
	"github.com/pablorobert/depscan/internal/model"
	"github.com/pablorobert/depscan/internal/registry"
)

// Options mirrors the flags that change what gets resolved.
type Options struct {
	// Wanted enables the expensive packument fetch that computes `wanted` for
	// packages whose latest falls outside the declared range.
	Wanted bool
	// SkipOutdated and SkipVulnerable come from --only-vulnerable and
	// --only-outdated. The suppressed axis reports not_checked, never clean.
	SkipOutdated   bool
	SkipVulnerable bool
	// Ignore holds advisory identifiers to drop, either numeric ids or GHSA ids.
	Ignore map[string]bool
}

// Clients bundles the two network clients.
type Clients struct {
	Registry *registry.Client
	Advisory *advisory.Client
}

// Run resolves every project in place.
func Run(ctx context.Context, projects []*model.Project, clients Clients, opts Options) {
	analyzable := make([]*model.Project, 0, len(projects))
	for _, p := range projects {
		// A project that failed during discovery or lockfile parsing already has its
		// statuses set to error and no dependency set to work with.
		if p.Outdated.Status == model.StatusError && p.Security.Status == model.StatusError {
			continue
		}
		analyzable = append(analyzable, p)
	}

	resolveOutdated(ctx, analyzable, clients.Registry, opts)
	resolveSecurity(ctx, analyzable, clients.Advisory, opts)

	for _, p := range projects {
		normalizeEmpty(p)
	}
}

// normalizeEmpty guarantees that both axes always carry a status and a non-nil slice,
// so no consumer can read an empty collection as "clean" by accident.
func normalizeEmpty(p *model.Project) {
	if p.Outdated.Status == "" {
		p.Outdated.Status = model.StatusNotChecked
	}
	if p.Security.Status == "" {
		p.Security.Status = model.StatusNotChecked
	}
	if p.Outdated.Packages == nil {
		p.Outdated.Packages = []model.OutdatedPackage{}
	}
	if p.Security.Packages == nil {
		p.Security.Packages = []model.VulnerablePackage{}
	}
	if p.Errors == nil {
		p.Errors = []model.ProjectError{}
	}
}

// resolveOutdated fetches `latest` for every unique direct dependency name, optionally
// fetches full version lists for the ones that need `wanted`, and then builds each
// project's outdated list.
//
// Outdated covers direct dependencies only: a transitive version is not something the
// project can bump. Security, by contrast, covers the whole lockfile.
func resolveOutdated(ctx context.Context, projects []*model.Project, client *registry.Client, opts Options) {
	if opts.SkipOutdated {
		for _, p := range projects {
			p.Outdated.Status = model.StatusNotChecked
		}
		return
	}

	names := uniqueDirectNames(projects)
	latest, failures := client.LatestBatch(ctx, names)

	// Second pass, only under --wanted: a package needs its full version list when
	// latest sits outside the declared range.
	versions := map[string][]string{}
	versionFailures := map[string]error{}
	if opts.Wanted {
		needed := namesNeedingVersions(projects, latest)
		if len(needed) > 0 {
			versions, versionFailures = client.VersionsBatch(ctx, needed)
		}
	}

	for _, p := range projects {
		buildOutdated(p, latest, failures, versions, versionFailures, opts)
	}
}

// uniqueDirectNames collects every direct dependency name that can be compared against
// the registry.
func uniqueDirectNames(projects []*model.Project) []string {
	set := make(map[string]bool)
	for _, p := range projects {
		for _, d := range p.Deps {
			if d.Direct && IsRegistryRange(d.Declared) {
				set[d.Name] = true
			}
		}
	}
	return sortedKeys(set)
}

// namesNeedingVersions returns the packages whose `wanted` cannot be proven equal to
// `latest` and therefore requires the packument.
func namesNeedingVersions(projects []*model.Project, latest map[string]string) []string {
	set := make(map[string]bool)
	for _, p := range projects {
		for _, d := range p.Deps {
			if !d.Direct || !IsRegistryRange(d.Declared) {
				continue
			}
			l, ok := latest[d.Name]
			if !ok || d.Version == "" {
				continue
			}
			if ClassifyUpdate(d.Version, l) == model.UpdateNone {
				continue
			}
			if accepts, parsed := Satisfies(d.Declared, l); parsed && accepts {
				// wanted == latest by local proof; no request needed.
				continue
			}
			set[d.Name] = true
		}
	}
	return sortedKeys(set)
}

// buildOutdated assembles one project's outdated list.
func buildOutdated(
	p *model.Project,
	latest map[string]string,
	failures map[string]error,
	versions map[string][]string,
	versionFailures map[string]error,
	opts Options,
) {
	var (
		out      []model.OutdatedPackage
		hadError bool
	)

	for _, d := range p.Deps {
		if !d.Direct {
			continue
		}
		if !IsRegistryRange(d.Declared) {
			// A workspace link or git dependency has no registry counterpart. Not an
			// error and not an omission worth reporting.
			continue
		}
		if d.Version == "" {
			p.AddError(model.ErrParseLockfile, model.PhaseOutdated,
				fmt.Sprintf("%s is declared but absent from the lockfile; its installed version is unknown", d.Name))
			hadError = true
			continue
		}

		l, ok := latest[d.Name]
		if !ok {
			msg := fmt.Sprintf("could not determine latest version of %s", d.Name)
			kind := model.ErrNetwork
			if err := failures[d.Name]; err != nil {
				msg = err.Error()
				kind = errorKind(err)
			}
			p.AddError(kind, model.PhaseOutdated, msg)
			hadError = true
			continue
		}

		latestType := ClassifyUpdate(d.Version, l)
		if latestType == model.UpdateNone {
			continue
		}

		entry := model.OutdatedPackage{
			Name:             d.Name,
			Declared:         d.Declared,
			Current:          d.Version,
			Latest:           l,
			LatestUpdateType: latestType,
			Direct:           true,
			Category:         d.CategoryOrNil(),
		}

		switch accepts, parsed := Satisfies(d.Declared, l); {
		case parsed && accepts:
			// The declared range accepts latest, so wanted equals latest by proof.
			wanted := l
			entry.Wanted = &wanted
			entry.WantedSource = model.WantedEqualsLatest
			entry.UpdateType = latestType

		case opts.Wanted:
			if vs, ok := versions[d.Name]; ok {
				if maxIn, found := MaxInRange(d.Declared, vs); found {
					entry.Wanted = &maxIn
					entry.WantedSource = model.WantedRegistry
					entry.UpdateType = ClassifyUpdate(d.Version, maxIn)
				} else {
					// The range matches nothing published; we know that much, but not
					// a wanted version.
					entry.WantedSource = model.WantedNotComputed
					entry.UpdateType = model.UpdateUnknown
				}
			} else {
				if err := versionFailures[d.Name]; err != nil {
					p.AddError(errorKind(err), model.PhaseOutdated, err.Error())
					hadError = true
				}
				entry.WantedSource = model.WantedNotComputed
				entry.UpdateType = model.UpdateUnknown
			}

		default:
			// Latest is outside the range and --wanted was not requested. Say so
			// rather than implying the package is current.
			entry.WantedSource = model.WantedNotComputed
			entry.UpdateType = model.UpdateUnknown
		}

		out = append(out, entry)
	}

	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	p.Outdated.Packages = out

	switch {
	case hadError && len(out) == 0:
		p.Outdated.Status = model.StatusError
	case len(out) > 0:
		p.Outdated.Status = model.StatusFindings
	default:
		p.Outdated.Status = model.StatusClean
	}
}

// resolveSecurity issues the bulk advisory query for every package version in the
// scan, then maps the answers back onto the projects.
func resolveSecurity(ctx context.Context, projects []*model.Project, client *advisory.Client, opts Options) {
	if opts.SkipVulnerable {
		for _, p := range projects {
			p.Security.Status = model.StatusNotChecked
		}
		return
	}

	request := make(map[string][]string)
	seen := make(map[string]bool)
	for _, p := range projects {
		for _, d := range p.Deps {
			if d.Version == "" {
				continue
			}
			key := d.Name + "@" + d.Version
			if seen[key] {
				continue
			}
			seen[key] = true
			request[d.Name] = append(request[d.Name], d.Version)
		}
	}

	found, err := client.Query(ctx, request)
	if err != nil {
		kind := errorKind(err)
		for _, p := range projects {
			p.Security.Status = model.StatusError
			p.AddError(kind, model.PhaseSecurity, err.Error())
		}
		return
	}

	for _, p := range projects {
		buildSecurity(p, found, opts)
	}
}

// buildSecurity assembles one project's vulnerability list.
//
// The bulk response is keyed by package and covers the union of versions submitted
// across every project, so each advisory is re-checked against this project's actual
// installed version.
func buildSecurity(p *model.Project, found map[string][]model.Advisory, opts Options) {
	var out []model.VulnerablePackage

	for _, d := range p.Deps {
		if d.Version == "" {
			continue
		}
		advs, ok := found[d.Name]
		if !ok {
			continue
		}

		matched := make([]model.Advisory, 0, len(advs))
		maxSeverity := model.SeverityUnknown
		ranges := make([]string, 0, len(advs))

		for _, a := range advs {
			if isIgnored(a, opts.Ignore) {
				continue
			}
			// An unparseable range counts as a match: a false positive is preferable
			// to concealing a vulnerability.
			hit, parsed := MatchesRange(d.Version, a.VulnerableVersions)
			if parsed && !hit {
				continue
			}
			matched = append(matched, a)
			maxSeverity = model.MaxSeverity(maxSeverity, a.Severity)
			ranges = append(ranges, a.VulnerableVersions)
		}
		if len(matched) == 0 {
			continue
		}

		vp := model.VulnerablePackage{
			Name:             d.Name,
			InstalledVersion: d.Version,
			MaxSeverity:      maxSeverity,
			Direct:           d.Direct,
			Category:         d.CategoryOrNil(),
			Advisories:       matched,
		}
		if fixed, ok := InferFixedVersion(ranges); ok {
			vp.FixedVersion = &fixed
			vp.FixedInferred = true
		}
		out = append(out, vp)
	}

	// Direct dependencies first, then by descending severity, then by name: what the
	// maintainer can act on comes first, and transitive findings are never hidden.
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Direct != out[j].Direct {
			return out[i].Direct
		}
		if out[i].MaxSeverity != out[j].MaxSeverity {
			return out[i].MaxSeverity.AtLeast(out[j].MaxSeverity)
		}
		return out[i].Name < out[j].Name
	})
	p.Security.Packages = out

	if len(out) > 0 {
		p.Security.Status = model.StatusFindings
	} else {
		p.Security.Status = model.StatusClean
	}
}

// isIgnored matches an advisory against the --ignore list, by numeric id or by the
// GHSA identifier embedded in its URL.
func isIgnored(a model.Advisory, ignore map[string]bool) bool {
	if len(ignore) == 0 {
		return false
	}
	if ignore[fmt.Sprint(a.ID)] {
		return true
	}
	if i := strings.LastIndex(a.URL, "/"); i >= 0 {
		if ignore[a.URL[i+1:]] {
			return true
		}
	}
	return false
}

// errorKind recovers the typed kind from a client error, defaulting to network.
// errors.As is required because the advisory client wraps its typed error with the
// attempt count before returning it.
func errorKind(err error) model.ErrorKind {
	if re, ok := errors.AsType[*registry.Error](err); ok {
		return re.Kind
	}
	if ae, ok := errors.AsType[*advisory.Error](err); ok {
		return ae.Kind
	}
	return model.ErrNetwork
}

func sortedKeys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
