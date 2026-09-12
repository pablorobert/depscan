// Package model holds the normalized representation of a scan, independent of any
// package manager. See SPEC.md sections 3, 8, 9, 10 and 12.
package model

// Status is the tri-state (quad-state, in practice) that every analysis axis carries.
// SPEC.md section 3: "clean" must never stand in for "I did not check".
type Status string

const (
	StatusClean      Status = "clean"
	StatusFindings   Status = "findings"
	StatusNotChecked Status = "not_checked"
	StatusError      Status = "error"
)

// Severity mirrors the npm advisory vocabulary exactly, so no translation is needed.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityModerate Severity = "moderate"
	SeverityLow      Severity = "low"
	SeverityUnknown  Severity = "unknown"
)

// rank orders severities for "max severity per package" and for --fail-on.
func (s Severity) rank() int {
	switch s {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityModerate:
		return 2
	case SeverityLow:
		return 1
	default:
		return 0
	}
}

// AtLeast reports whether s is as severe as threshold.
func (s Severity) AtLeast(threshold Severity) bool {
	return s.rank() >= threshold.rank()
}

// MaxSeverity returns the most severe of a and b.
func MaxSeverity(a, b Severity) Severity {
	if b.rank() > a.rank() {
		return b
	}
	return a
}

// ParseSeverity normalizes an incoming severity string, defaulting to unknown rather
// than guessing.
func ParseSeverity(s string) Severity {
	switch Severity(s) {
	case SeverityCritical, SeverityHigh, SeverityModerate, SeverityLow:
		return Severity(s)
	default:
		return SeverityUnknown
	}
}

// UpdateType classifies a version jump. "unknown" is used whenever semver does not
// apply (git URLs, file:, workspace:, dist-tags) — never invented.
type UpdateType string

const (
	UpdatePatch   UpdateType = "patch"
	UpdateMinor   UpdateType = "minor"
	UpdateMajor   UpdateType = "major"
	UpdateNone    UpdateType = "none"
	UpdateUnknown UpdateType = "unknown"
)

// WantedSource records the provenance of the Wanted field. SPEC.md section 9.2:
// "equals-latest" is only emitted where the inference is demonstrable.
type WantedSource string

const (
	// WantedEqualsLatest means the declared range accepts Latest, so Wanted == Latest
	// by local proof — no request needed.
	WantedEqualsLatest WantedSource = "equals-latest"
	// WantedRegistry means the full version list was fetched and the maximum in-range
	// version was computed.
	WantedRegistry WantedSource = "registry"
	// WantedNotComputed means Latest falls outside the declared range and --wanted was
	// not requested. Wanted is nil and no consumer may treat the package as current.
	WantedNotComputed WantedSource = "not-computed"
)

// Category is the package.json section a dependency was declared in. It is orthogonal
// to Direct: a transitive dependency has no category (nil), and "transitive" is never
// a category value. SPEC.md section 8.
type Category string

const (
	CategoryProd     Category = "dependency"
	CategoryDev      Category = "devDependency"
	CategoryPeer     Category = "peerDependency"
	CategoryOptional Category = "optionalDependency"
)

// ErrorKind is a closed enum so consumers can branch on failures. SPEC.md section 12.
type ErrorKind string

const (
	ErrNoLockfile                ErrorKind = "no_lockfile"
	ErrBinaryLockfileNoBun       ErrorKind = "binary_lockfile_no_bun"
	ErrParsePackageJSON          ErrorKind = "parse_package_json"
	ErrParseLockfile             ErrorKind = "parse_lockfile"
	ErrUnsupportedLockfileFormat ErrorKind = "unsupported_lockfile_version"
	ErrNetwork                   ErrorKind = "network"
	ErrTimeout                   ErrorKind = "timeout"
	ErrCacheMissOffline          ErrorKind = "cache_miss_offline"
	ErrInternal                  ErrorKind = "internal"
)

// Phase says which stage of the scan an error belongs to.
type Phase string

const (
	PhaseDiscovery Phase = "discovery"
	PhaseLockfile  Phase = "lockfile"
	PhaseOutdated  Phase = "outdated"
	PhaseSecurity  Phase = "security"
)

// ProjectError associates a failure with the project it affects, so one broken project
// never aborts the scan.
type ProjectError struct {
	Kind    ErrorKind `json:"kind"`
	Phase   Phase     `json:"phase"`
	Message string    `json:"message"`
}

// Dep is a resolved dependency taken from the lockfile. It is internal to the scan and
// is not serialized directly.
type Dep struct {
	Name     string
	Version  string // resolved version from the lockfile
	Declared string // the range from package.json; empty for transitive deps
	Direct   bool
	Category Category // empty for transitive deps
}

// CategoryOrNil renders the category as a nullable JSON value.
func (d Dep) CategoryOrNil() *Category {
	if d.Category == "" {
		return nil
	}
	c := d.Category
	return &c
}

// OutdatedPackage carries the three distinct versions plus the provenance of Wanted.
type OutdatedPackage struct {
	Name             string       `json:"name"`
	Declared         string       `json:"declared"`
	Current          string       `json:"current"`
	Wanted           *string      `json:"wanted"`
	Latest           string       `json:"latest"`
	UpdateType       UpdateType   `json:"updateType"`
	LatestUpdateType UpdateType   `json:"latestUpdateType"`
	WantedSource     WantedSource `json:"wantedSource"`
	Direct           bool         `json:"direct"`
	Category         *Category    `json:"category"`
}

// CVSS is the advisory score as returned by the registry; VectorString is frequently
// null upstream.
type CVSS struct {
	Score        float64 `json:"score"`
	VectorString *string `json:"vectorString"`
}

// Advisory is one security advisory, preserved verbatim from the registry.
type Advisory struct {
	ID                 int      `json:"id"`
	URL                string   `json:"url"`
	Title              string   `json:"title"`
	Severity           Severity `json:"severity"`
	VulnerableVersions string   `json:"vulnerableVersions"`
	CWE                []string `json:"cwe"`
	CVSS               CVSS     `json:"cvss"`
}

// VulnerablePackage groups every advisory affecting one installed package version.
// SPEC.md section 10.4: the human-facing count is affected packages, not advisories.
type VulnerablePackage struct {
	Name             string     `json:"name"`
	InstalledVersion string     `json:"installedVersion"`
	MaxSeverity      Severity   `json:"maxSeverity"`
	Direct           bool       `json:"direct"`
	Category         *Category  `json:"category"`
	FixedVersion     *string    `json:"fixedVersion"`
	FixedInferred    bool       `json:"fixedVersionInferred"`
	Advisories       []Advisory `json:"advisories"`
}

// OutdatedResult is the outdated axis of one project, always carrying a Status.
type OutdatedResult struct {
	Status   Status            `json:"status"`
	Packages []OutdatedPackage `json:"packages"`
}

// SecurityResult is the security axis of one project, always carrying a Status.
type SecurityResult struct {
	Status   Status              `json:"status"`
	Packages []VulnerablePackage `json:"packages"`
}

// Project is one discovered package.json and everything learned about it.
type Project struct {
	Path           string         `json:"path"`
	Name           string         `json:"name"`
	PackageManager string         `json:"packageManager"`
	Lockfile       string         `json:"lockfile"`
	WorkspaceRoot  *string        `json:"workspaceRoot"`
	Outdated       OutdatedResult `json:"outdated"`
	Security       SecurityResult `json:"security"`
	Errors         []ProjectError `json:"errors"`

	// Deps is the resolved dependency set from the lockfile, used to build the network
	// batches. Not serialized.
	Deps []Dep `json:"-"`
}

// AddError appends a failure to the project.
func (p *Project) AddError(kind ErrorKind, phase Phase, msg string) {
	p.Errors = append(p.Errors, ProjectError{Kind: kind, Phase: phase, Message: msg})
}

// FullyAnalyzed reports whether both axes reached a verified conclusion.
func (p *Project) FullyAnalyzed() bool {
	return isVerified(p.Outdated.Status) && isVerified(p.Security.Status)
}

// Incomplete reports whether either axis was left unverified.
func (p *Project) Incomplete() bool {
	return !p.FullyAnalyzed()
}

func isVerified(s Status) bool {
	return s == StatusClean || s == StatusFindings
}

// SeverityCounts is a fixed-field map so JSON output stays deterministic.
type SeverityCounts struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Moderate int `json:"moderate"`
	Low      int `json:"low"`
	Unknown  int `json:"unknown"`
}

// Add increments the bucket for one severity.
func (c *SeverityCounts) Add(s Severity) {
	switch s {
	case SeverityCritical:
		c.Critical++
	case SeverityHigh:
		c.High++
	case SeverityModerate:
		c.Moderate++
	case SeverityLow:
		c.Low++
	default:
		c.Unknown++
	}
}

// UpdateTypeCounts is a fixed-field map so JSON output stays deterministic.
type UpdateTypeCounts struct {
	Patch   int `json:"patch"`
	Minor   int `json:"minor"`
	Major   int `json:"major"`
	Unknown int `json:"unknown"`
}

// Add increments the bucket for one update type.
func (c *UpdateTypeCounts) Add(u UpdateType) {
	switch u {
	case UpdatePatch:
		c.Patch++
	case UpdateMinor:
		c.Minor++
	case UpdateMajor:
		c.Major++
	default:
		c.Unknown++
	}
}

// Summary is the aggregate view. SPEC.md section 10.4.
type Summary struct {
	Projects           int              `json:"projects"`
	FullyAnalyzed      int              `json:"fullyAnalyzed"`
	OutdatedPackages   int              `json:"outdatedPackages"`
	VulnerablePackages int              `json:"vulnerablePackages"`
	Advisories         int              `json:"advisories"`
	BySeverity         SeverityCounts   `json:"bySeverity"`
	ByUpdateType       UpdateTypeCounts `json:"byUpdateType"`
	ProjectsNotChecked int              `json:"projectsNotChecked"`
	ProjectsWithErrors int              `json:"projectsWithErrors"`
}

// Options records the switches a run was made with, so a stored report stays
// interpretable.
type Options struct {
	Offline bool `json:"offline"`
	Wanted  bool `json:"wanted"`
	Cache   bool `json:"cache"`
}

// Report is the top-level document emitted by --json.
type Report struct {
	Root           string     `json:"root"`
	DepscanVersion string     `json:"depscanVersion"`
	StartedAt      string     `json:"startedAt"`
	DurationMs     int64      `json:"durationMs"`
	Options        Options    `json:"options"`
	Projects       []*Project `json:"projects"`
	Summary        Summary    `json:"summary"`
}

// BuildSummary recomputes the aggregate counters from the projects.
func (r *Report) BuildSummary() {
	s := Summary{Projects: len(r.Projects)}
	for _, p := range r.Projects {
		if p.FullyAnalyzed() {
			s.FullyAnalyzed++
		}
		if p.Outdated.Status == StatusNotChecked || p.Security.Status == StatusNotChecked {
			s.ProjectsNotChecked++
		}
		if len(p.Errors) > 0 {
			s.ProjectsWithErrors++
		}
		for _, o := range p.Outdated.Packages {
			s.OutdatedPackages++
			s.ByUpdateType.Add(o.LatestUpdateType)
		}
		for _, v := range p.Security.Packages {
			s.VulnerablePackages++
			s.Advisories += len(v.Advisories)
			s.BySeverity.Add(v.MaxSeverity)
		}
	}
	r.Summary = s
}

// HasFindingsAtLeast reports whether any vulnerability reaches the threshold.
func (r *Report) HasFindingsAtLeast(threshold Severity) bool {
	for _, p := range r.Projects {
		for _, v := range p.Security.Packages {
			if v.MaxSeverity.AtLeast(threshold) {
				return true
			}
		}
	}
	return false
}

// HasOutdated reports whether any project has an outdated package.
func (r *Report) HasOutdated() bool {
	for _, p := range r.Projects {
		if len(p.Outdated.Packages) > 0 {
			return true
		}
	}
	return false
}

// AnyIncomplete reports whether any project was left unverified on either axis.
func (r *Report) AnyIncomplete() bool {
	for _, p := range r.Projects {
		if p.Incomplete() {
			return true
		}
	}
	return false
}
