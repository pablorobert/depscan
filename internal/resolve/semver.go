package resolve

import (
	"sort"
	"strings"

	"github.com/Masterminds/semver/v3"

	"github.com/pablorobert/depscan/internal/model"
)

// ClassifyUpdate compares two versions and reports the kind of jump between them.
// Anything that is not a pair of parseable semver versions yields UpdateUnknown —
// a classification is never invented. SPEC.md section 9.1.
func ClassifyUpdate(current, target string) model.UpdateType {
	cv, err := semver.NewVersion(strings.TrimSpace(current))
	if err != nil {
		return model.UpdateUnknown
	}
	tv, err := semver.NewVersion(strings.TrimSpace(target))
	if err != nil {
		return model.UpdateUnknown
	}

	switch {
	case tv.Equal(cv):
		return model.UpdateNone
	case tv.LessThan(cv):
		// The lockfile is ahead of the registry's latest, which happens with
		// prereleases and with unpublished versions. Not an update.
		return model.UpdateNone
	case tv.Major() != cv.Major():
		return model.UpdateMajor
	case tv.Minor() != cv.Minor():
		return model.UpdateMinor
	default:
		return model.UpdatePatch
	}
}

// IsRegistryRange reports whether a declared range refers to a registry version at
// all. Workspace links, file paths, git URLs and aliases cannot be compared against
// the registry and are excluded from outdated reporting rather than misreported.
func IsRegistryRange(declared string) bool {
	d := strings.TrimSpace(declared)
	if d == "" {
		return false
	}
	for _, prefix := range []string{
		"workspace:", "link:", "file:", "portal:", "git:", "git+", "npm:",
		"http:", "https:", "patch:", "github:",
	} {
		if strings.HasPrefix(d, prefix) {
			return false
		}
	}
	// "user/repo" shorthand for a GitHub dependency.
	if strings.Contains(d, "/") && !strings.ContainsAny(d, "<>=^~") {
		return false
	}
	return true
}

// Satisfies reports whether version falls inside the declared range. The second
// return value is false when the range or the version could not be parsed, in which
// case the caller must not draw a conclusion.
func Satisfies(declared, version string) (ok bool, parsed bool) {
	c, err := parseConstraint(declared)
	if err != nil {
		return false, false
	}
	v, err := semver.NewVersion(strings.TrimSpace(version))
	if err != nil {
		return false, false
	}
	return c.Check(v), true
}

// MaxInRange returns the highest version in versions that satisfies declared.
// Prereleases are excluded unless the declared range itself mentions one, matching
// what a package manager would install.
func MaxInRange(declared string, versions []string) (string, bool) {
	c, err := parseConstraint(declared)
	if err != nil {
		return "", false
	}
	allowPre := strings.Contains(declared, "-")

	candidates := make([]*semver.Version, 0, len(versions))
	for _, raw := range versions {
		v, err := semver.NewVersion(strings.TrimSpace(raw))
		if err != nil {
			continue
		}
		if v.Prerelease() != "" && !allowPre {
			continue
		}
		if c.Check(v) {
			candidates = append(candidates, v)
		}
	}
	if len(candidates) == 0 {
		return "", false
	}
	sort.Sort(semver.Collection(candidates))
	return candidates[len(candidates)-1].Original(), true
}

// MatchesRange reports whether version falls inside an advisory's vulnerable_versions
// range, such as ">=1.0.0 <1.8.2".
//
// The second return value is false when the range could not be parsed. Callers treat
// that as a match: a false positive is preferable to hiding a vulnerability.
func MatchesRange(version, rng string) (matches bool, parsed bool) {
	return Satisfies(rng, version)
}

// parseConstraint builds a constraint from an npm-style range.
//
// npm uses whitespace for conjunction (">=1.0.0 <2.0.0") while the semver library
// expects commas, so a fallback rewrite is attempted. Hyphen ranges ("1.2 - 1.5")
// depend on their surrounding spaces and are left alone.
func parseConstraint(declared string) (*semver.Constraints, error) {
	d := strings.TrimSpace(declared)
	if d == "" || d == "*" || strings.EqualFold(d, "latest") || strings.EqualFold(d, "x") {
		d = "*"
	}

	c, err := semver.NewConstraint(d)
	if err == nil {
		return c, nil
	}
	if strings.Contains(d, " - ") {
		return nil, err
	}
	return semver.NewConstraint(conjoin(d))
}

// conjoin turns whitespace conjunction into the comma form the library understands,
// preserving the "||" disjunction between groups.
func conjoin(d string) string {
	groups := strings.Split(d, "||")
	for i, g := range groups {
		parts := strings.Fields(g)
		groups[i] = strings.Join(parts, ",")
	}
	return strings.Join(groups, "||")
}

// InferFixedVersion derives the first version known to be safe from every vulnerable
// range affecting one package. SPEC.md section 10.3.
//
// Each range constrains the answer differently:
//
//	"<1.8.2"    names a safe version: 1.8.2
//	"<=1.13.4"  names no version, only a floor the answer must exceed
//	no upper bound at all leaves the package vulnerable at every known version
//
// The result is the highest named safe version, but only when it clears every floor.
// If the tallest constraint is a floor — or there is no named version at all — the fix
// cannot be named and the caller must report null rather than guess.
func InferFixedVersion(ranges []string) (string, bool) {
	var (
		highestNamed *semver.Version
		highestFloor *semver.Version
	)

	for _, rng := range ranges {
		bound, inclusive, ok := upperBound(rng)
		if !ok {
			// No upper bound: no version is known to be safe.
			return "", false
		}
		v, err := semver.NewVersion(bound)
		if err != nil {
			return "", false
		}
		if inclusive {
			if highestFloor == nil || v.GreaterThan(highestFloor) {
				highestFloor = v
			}
			continue
		}
		if highestNamed == nil || v.GreaterThan(highestNamed) {
			highestNamed = v
		}
	}

	if highestNamed == nil {
		return "", false
	}
	if highestFloor != nil && !highestNamed.GreaterThan(highestFloor) {
		// Some advisory is still unfixed at the highest version we can name.
		return "", false
	}
	return highestNamed.Original(), true
}

// upperBound extracts the upper bound of a vulnerable range. It reports whether the
// bound is inclusive ("<=") and whether a bound was found at all. A range with two
// upper bounds is not a shape worth reasoning about and is rejected.
func upperBound(rng string) (bound string, inclusive bool, ok bool) {
	found := ""
	isInclusive := false

	for part := range strings.FieldsSeq(strings.ReplaceAll(rng, ",", " ")) {
		var candidate string
		switch {
		case strings.HasPrefix(part, "<="):
			candidate = strings.TrimSpace(strings.TrimPrefix(part, "<="))
			if found != "" {
				return "", false, false
			}
			found, isInclusive = candidate, true
		case strings.HasPrefix(part, "<"):
			candidate = strings.TrimSpace(strings.TrimPrefix(part, "<"))
			if found != "" {
				return "", false, false
			}
			found, isInclusive = candidate, false
		}
	}
	if found == "" {
		return "", false, false
	}
	return found, isInclusive, true
}
