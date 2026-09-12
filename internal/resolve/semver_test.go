package resolve

import (
	"testing"

	"github.com/pablorobert/depscan/internal/model"
)

func TestClassifyUpdate(t *testing.T) {
	cases := []struct {
		current, target string
		want            model.UpdateType
	}{
		{"7.1.3", "7.1.5", model.UpdatePatch},
		{"9.32.0", "9.35.0", model.UpdateMinor},
		{"18.3.0", "19.0.0", model.UpdateMajor},
		{"1.0.0", "1.0.0", model.UpdateNone},
		{"2.0.0", "1.9.9", model.UpdateNone}, // lockfile ahead of the registry
		{"0.21.5", "0.25.0", model.UpdateMinor},
		{"1.0.0-beta.1", "1.0.0", model.UpdatePatch},
		{"not-a-version", "1.0.0", model.UpdateUnknown},
		{"1.0.0", "also-not", model.UpdateUnknown},
		{"", "", model.UpdateUnknown},
	}
	for _, c := range cases {
		if got := ClassifyUpdate(c.current, c.target); got != c.want {
			t.Errorf("ClassifyUpdate(%q, %q) = %q, want %q", c.current, c.target, got, c.want)
		}
	}
}

func TestIsRegistryRange(t *testing.T) {
	registry := []string{"^1.6.0", "~2.0", "1.2.3", ">=1.0.0 <2.0.0", "*", "latest", "1.x"}
	notRegistry := []string{
		"", "workspace:*", "file:../vendored", "link:../x", "npm:other@1.0.0",
		"git+https://example.invalid/a.git", "github:owner/repo", "owner/repo",
	}

	for _, r := range registry {
		if !IsRegistryRange(r) {
			t.Errorf("%q should be a registry range", r)
		}
	}
	for _, r := range notRegistry {
		if IsRegistryRange(r) {
			t.Errorf("%q should not be a registry range", r)
		}
	}
}

func TestSatisfies(t *testing.T) {
	cases := []struct {
		declared, version string
		want, parsed      bool
	}{
		{"^1.6.0", "1.20.0", true, true},
		{"^1.6.0", "2.0.0", false, true},
		{"~1.6.0", "1.6.9", true, true},
		{"~1.6.0", "1.7.0", false, true},
		{"18.2.0", "18.2.0", true, true},
		{"18.2.0", "19.0.0", false, true},
		{">=1.0.0 <2.0.0", "1.5.0", true, true}, // npm whitespace conjunction
		{">=1.0.0 <2.0.0", "2.0.1", false, true},
		{"*", "9.9.9", true, true},
		{"^1.0.0 || ^2.0.0", "2.3.4", true, true},
		{"totally bogus", "1.0.0", false, false},
		{"^1.0.0", "not-a-version", false, false},
	}
	for _, c := range cases {
		got, parsed := Satisfies(c.declared, c.version)
		if parsed != c.parsed {
			t.Errorf("Satisfies(%q, %q) parsed = %v, want %v", c.declared, c.version, parsed, c.parsed)
			continue
		}
		if parsed && got != c.want {
			t.Errorf("Satisfies(%q, %q) = %v, want %v", c.declared, c.version, got, c.want)
		}
	}
}

func TestMaxInRange(t *testing.T) {
	versions := []string{"1.5.0", "1.6.0", "1.18.0", "1.20.0", "2.0.0", "2.1.0-beta.1"}

	if got, ok := MaxInRange("^1.6.0", versions); !ok || got != "1.20.0" {
		t.Errorf("MaxInRange(^1.6.0) = (%q, %v), want 1.20.0", got, ok)
	}
	if got, ok := MaxInRange("~1.6.0", versions); !ok || got != "1.6.0" {
		t.Errorf("MaxInRange(~1.6.0) = (%q, %v), want 1.6.0", got, ok)
	}
	if _, ok := MaxInRange("^9.0.0", versions); ok {
		t.Error("a range matching nothing published must report not found")
	}
	if _, ok := MaxInRange("nonsense range", versions); ok {
		t.Error("an unparseable range must report not found")
	}
}

func TestMaxInRangeExcludesPrereleasesByDefault(t *testing.T) {
	versions := []string{"1.0.0", "2.0.0-rc.1"}
	if got, ok := MaxInRange(">=1.0.0", versions); !ok || got != "1.0.0" {
		t.Errorf("MaxInRange = (%q, %v), want 1.0.0 with the prerelease excluded", got, ok)
	}
}

func TestInferFixedVersion(t *testing.T) {
	cases := []struct {
		name   string
		ranges []string
		want   string
		ok     bool
	}{
		{
			name:   "single exclusive upper bound",
			ranges: []string{">=1.0.0 <1.8.2"},
			want:   "1.8.2",
			ok:     true,
		},
		{
			name:   "highest bound across advisories wins",
			ranges: []string{">=1.0.0 <1.8.2", ">=1.0.0 <1.18.0", ">=1.0.0 <1.12.0"},
			want:   "1.18.0",
			ok:     true,
		},
		{
			name:   "inclusive upper bound is not a fix",
			ranges: []string{">=1.0.0 <=1.13.4"},
			ok:     false,
		},
		{
			name:   "an inclusive floor above every named version blocks the inference",
			ranges: []string{">=1.0.0 <1.8.2", "<=1.13.4"},
			ok:     false,
		},
		{
			// The real axios shape: dozens of advisories, some with inclusive bounds,
			// but a named version that clears all of them.
			name:   "a named version clearing every inclusive floor is reported",
			ranges: []string{">=1.0.0 <1.18.0", ">=1.0.0 <=1.13.4", ">=1.3.2 <=1.7.3"},
			want:   "1.18.0",
			ok:     true,
		},
		{
			name:   "equal to the floor is not above it",
			ranges: []string{"<1.13.4", "<=1.13.4"},
			ok:     false,
		},
		{
			name:   "no upper bound at all",
			ranges: []string{">=1.0.0"},
			ok:     false,
		},
		{
			name:   "empty input",
			ranges: nil,
			ok:     false,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := InferFixedVersion(c.ranges)
			if ok != c.ok {
				t.Fatalf("ok = %v, want %v (got %q)", ok, c.ok, got)
			}
			if ok && got != c.want {
				t.Fatalf("fixed = %q, want %q", got, c.want)
			}
		})
	}
}

func TestMatchesRangeUsesAdvisoryShapes(t *testing.T) {
	// The exact shapes the bulk advisory endpoint returns.
	if hit, parsed := MatchesRange("1.6.0", ">=1.0.0 <1.8.2"); !parsed || !hit {
		t.Errorf("1.6.0 should match >=1.0.0 <1.8.2 (parsed=%v)", parsed)
	}
	if hit, parsed := MatchesRange("1.20.0", ">=1.0.0 <1.8.2"); !parsed || hit {
		t.Errorf("1.20.0 should not match >=1.0.0 <1.8.2 (parsed=%v)", parsed)
	}
	if hit, parsed := MatchesRange("5.4.19", "<=5.4.19"); !parsed || !hit {
		t.Errorf("5.4.19 should match <=5.4.19 (parsed=%v)", parsed)
	}
}
