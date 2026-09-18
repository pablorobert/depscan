// Package output renders a scan report for humans and for machines.
package output

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/pablorobert/depscan/internal/model"
)

// Style decides which decorations are safe for the destination terminal.
type Style struct {
	Color   bool
	Unicode bool
}

// DetectStyle inspects the environment. Color is only used as an enhancement: with it
// disabled the output must still be fully understandable, so every marker is also
// spelled out in words.
func DetectStyle(w io.Writer) Style {
	s := Style{}

	if os.Getenv("NO_COLOR") == "" && os.Getenv("TERM") != "dumb" {
		if f, ok := w.(*os.File); ok {
			if st, err := f.Stat(); err == nil && st.Mode()&os.ModeCharDevice != 0 {
				s.Color = true
			}
		}
	}

	// Legacy Windows consoles mangle box-drawing characters, so they are only used
	// where the environment advertises a modern terminal.
	s.Unicode = runtime.GOOS != "windows" ||
		os.Getenv("WT_SESSION") != "" ||
		os.Getenv("TERM") != "" ||
		os.Getenv("ConEmuANSI") == "ON"

	return s
}

const (
	colReset  = "\033[0m"
	colDim    = "\033[2m"
	colRed    = "\033[31m"
	colYellow = "\033[33m"
	colGreen  = "\033[32m"
	colBold   = "\033[1m"
)

func (s Style) paint(code, text string) string {
	if !s.Color {
		return text
	}
	return code + text + colReset
}

func (s Style) rule(n int) string {
	if s.Unicode {
		return strings.Repeat("─", n)
	}
	return strings.Repeat("-", n)
}

// marker returns the per-project status glyph. A vulnerability outranks an error: a
// project with a HIGH finding and a failed lookup elsewhere must not be softened to a
// warning. A plain check is reserved for a project that was fully verified and clean.
func (s Style) marker(p *model.Project) string {
	switch {
	case len(p.Security.Packages) > 0:
		return s.paint(colRed, s.glyph("✗", "x"))
	case hasErrors(p) ||
		p.Outdated.Status == model.StatusError || p.Security.Status == model.StatusError ||
		p.Outdated.Status == model.StatusNotChecked || p.Security.Status == model.StatusNotChecked:
		return s.paint(colYellow, s.glyph("⚠", "!"))
	case len(p.Outdated.Packages) > 0:
		return s.paint(colYellow, s.glyph("⚠", "!"))
	default:
		return s.paint(colGreen, s.glyph("✓", "+"))
	}
}

func (s Style) glyph(unicode, ascii string) string {
	if s.Unicode {
		return unicode
	}
	return ascii
}

// Terminal writes the human-readable report.
type Terminal struct {
	w     io.Writer
	style Style
	quiet bool
	// directOnly hides transitive findings from the display only; they remain in the
	// JSON document and in the summary counts.
	directOnly bool
}

// NewTerminal builds a terminal renderer.
func NewTerminal(w io.Writer, quiet, directOnly bool) *Terminal {
	return &Terminal{w: w, style: DetectStyle(w), quiet: quiet, directOnly: directOnly}
}

// Scanning announces the root being walked. Suppressed by --quiet.
func (t *Terminal) Scanning(root string) {
	if t.quiet {
		return
	}
	fmt.Fprintf(t.w, "%s\n\n", t.style.paint(colBold, "depscan"))
	fmt.Fprintf(t.w, "Scanning %s ...\n\n", root)
}

// Found announces how many projects were discovered. Suppressed by --quiet.
func (t *Terminal) Found(n int) {
	if t.quiet {
		return
	}
	fmt.Fprintf(t.w, "Found %d project%s\n\n", n, plural(n))
}

// Report writes the per-project detail and the summary.
func (t *Terminal) Report(r *model.Report) {
	s := t.style
	labels := displayNames(r)

	for _, p := range r.Projects {
		fmt.Fprintf(t.w, "%s %s\n", s.marker(p), s.paint(colBold, labels[p.Path]))
		t.projectBody(p)
		fmt.Fprintln(t.w)
	}

	fmt.Fprintln(t.w, s.rule(38))
	sum := r.Summary
	fmt.Fprintf(t.w, "Projects:            %d\n", sum.Projects)
	fmt.Fprintf(t.w, "Fully analyzed:      %d\n", sum.FullyAnalyzed)
	fmt.Fprintf(t.w, "Outdated packages:   %d\n", sum.OutdatedPackages)
	fmt.Fprintf(t.w, "Affected packages:   %d   (advisories: %d)\n",
		sum.VulnerablePackages, sum.Advisories)
	if sum.ProjectsNotChecked > 0 {
		fmt.Fprintf(t.w, "Not checked:         %d\n", sum.ProjectsNotChecked)
	}
	if sum.ProjectsWithErrors > 0 {
		fmt.Fprintf(t.w, "With errors:         %d\n", sum.ProjectsWithErrors)
	}
	fmt.Fprintf(t.w, "\nCompleted in %s\n", humanMillis(r.DurationMs))
}

// projectBody renders one project's findings, statuses and errors.
func (t *Terminal) projectBody(p *model.Project) {
	s := t.style
	wrote := false

	switch p.Outdated.Status {
	case model.StatusFindings:
		wrote = true
		fmt.Fprintf(t.w, "    %d outdated\n", len(p.Outdated.Packages))
		heldBack := false
		for _, o := range p.Outdated.Packages {
			t.outdatedLine(o)
			if o.ReleaseAge != nil && o.ReleaseAge.Status == model.ReleaseAgeHeldBack {
				heldBack = true
			}
		}
		if heldBack {
			fmt.Fprintf(t.w, "      %s\n", s.paint(colDim, fmt.Sprintf(
				"* published less than %s ago; %s skips it (minimumReleaseAge in %s)",
				humanSeconds(p.MinimumReleaseAge.Seconds), p.PackageManager, p.MinimumReleaseAge.Source)))
		}
	case model.StatusClean:
		wrote = true
		fmt.Fprintf(t.w, "    dependencies up to date\n")
	case model.StatusNotChecked:
		wrote = true
		fmt.Fprintf(t.w, "    %s\n", s.paint(colDim, "outdated: not checked"))
	case model.StatusError:
		wrote = true
		fmt.Fprintf(t.w, "    %s\n", s.paint(colYellow, "outdated: could not be determined"))
	}

	switch p.Security.Status {
	case model.StatusFindings:
		wrote = true
		t.securityBlock(p)
	case model.StatusClean:
		// Only worth a line when nothing else was said about the project.
		if len(p.Outdated.Packages) == 0 {
			fmt.Fprintf(t.w, "    no advisories\n")
			wrote = true
		}
	case model.StatusNotChecked:
		wrote = true
		fmt.Fprintf(t.w, "    %s\n",
			s.paint(colYellow, "Security information unavailable — not checked"))
	case model.StatusError:
		wrote = true
		fmt.Fprintf(t.w, "    %s\n",
			s.paint(colYellow, "Security information unavailable"))
	}

	for _, e := range p.Errors {
		wrote = true
		fmt.Fprintf(t.w, "    %s %s\n", s.paint(colDim, string(e.Kind)+":"), e.Message)
	}

	if !wrote {
		fmt.Fprintf(t.w, "    nothing to report\n")
	}
}

// outdatedLine renders one outdated package, naming explicitly when `wanted` was not
// computed so the reader never mistakes it for "already current".
func (t *Terminal) outdatedLine(o model.OutdatedPackage) {
	target := o.Latest
	kind := string(o.LatestUpdateType)
	note := ""

	switch o.WantedSource {
	case model.WantedEqualsLatest:
		// current -> latest is the whole story.
	case model.WantedRegistry:
		if o.Wanted != nil && *o.Wanted != o.Latest {
			note = fmt.Sprintf("  (in range: %s %s; latest %s %s)",
				*o.Wanted, o.UpdateType, o.Latest, o.LatestUpdateType)
		}
	case model.WantedNotComputed:
		note = "  (wanted not computed — use --wanted)"
	}

	if ra := o.ReleaseAge; ra != nil {
		switch ra.Status {
		case model.ReleaseAgeHeldBack:
			// Mirrors bun outdated: the star says latest is too recent to install.
			target += "*"
			switch {
			case ra.Eligible == nil:
				note = "  (no release old enough yet)"
			case *ra.Eligible == o.Current:
				note = "  (nothing installable yet)"
			case o.Wanted != nil && *o.Wanted != *ra.Eligible:
				note = fmt.Sprintf("  (installable: %s in range, %s latest)", *o.Wanted, *ra.Eligible)
			default:
				note = fmt.Sprintf("  (installable: %s)", *ra.Eligible)
			}
		case model.ReleaseAgeNotChecked:
			note += "  (release age not checked)"
		}
	}

	fmt.Fprintf(t.w, "      %-24s %s %s %-8s %s%s\n",
		o.Name, o.Current, t.style.glyph("→", "->"), target, kind, note)
}

// humanSeconds renders a release-age window the way people configure it: 259200 is
// "72h", not "259200s".
func humanSeconds(s int64) string {
	switch {
	case s%3600 == 0:
		return fmt.Sprintf("%dh", s/3600)
	case s%60 == 0:
		return fmt.Sprintf("%dmin", s/60)
	default:
		return fmt.Sprintf("%ds", s)
	}
}

// securityBlock renders vulnerabilities grouped by direct and transitive. Direct
// findings come first because that is what the maintainer can act on, and transitive
// findings are always shown: one of them may be the one that matters.
func (t *Terminal) securityBlock(p *model.Project) {
	var direct, transitive []model.VulnerablePackage
	for _, v := range p.Security.Packages {
		if v.Direct {
			direct = append(direct, v)
		} else {
			transitive = append(transitive, v)
		}
	}

	n := len(p.Security.Packages)
	fmt.Fprintf(t.w, "    %d affected package%s", n, plural(n))
	if t.directOnly && len(transitive) > 0 {
		fmt.Fprintf(t.w, " %s",
			t.style.paint(colDim, fmt.Sprintf("(%d transitive hidden by --direct-only)", len(transitive))))
	}
	fmt.Fprintln(t.w)

	if t.directOnly {
		transitive = nil
	}

	for _, group := range []struct {
		label string
		items []model.VulnerablePackage
	}{
		{"direct", direct},
		{"transitive", transitive},
	} {
		if len(group.items) == 0 {
			continue
		}
		fmt.Fprintf(t.w, "\n      %s\n", t.style.paint(colDim, group.label))
		for _, v := range group.items {
			fix := "fix unknown"
			if v.FixedVersion != nil {
				fix = fmt.Sprintf("%s %s %s", v.InstalledVersion, t.style.glyph("→", "->"), *v.FixedVersion)
			}
			count := fmt.Sprintf("%d advisor%s", len(v.Advisories), pluralY(len(v.Advisories)))
			fmt.Fprintf(t.w, "        %-24s %s %-14s %s\n",
				v.Name,
				t.severityLabel(v.MaxSeverity, 10),
				count,
				fix)
		}
	}
}

// severityLabel pads before painting, because escape sequences count as characters
// in a width-limited format verb and would break the column alignment.
func (t *Terminal) severityLabel(s model.Severity, width int) string {
	label := fmt.Sprintf("%-*s", width, strings.ToUpper(string(s)))
	switch s {
	case model.SeverityCritical, model.SeverityHigh:
		return t.style.paint(colRed, label)
	case model.SeverityModerate:
		return t.style.paint(colYellow, label)
	default:
		return label
	}
}

// displayNames labels each project by its package name, falling back to the path
// relative to the scan root whenever a name is shared by more than one project.
// Several projects called "app" are otherwise indistinguishable in the output.
func displayNames(r *model.Report) map[string]string {
	count := make(map[string]int, len(r.Projects))
	for _, p := range r.Projects {
		count[p.Name]++
	}

	out := make(map[string]string, len(r.Projects))
	for _, p := range r.Projects {
		label := p.Name
		if count[p.Name] > 1 {
			if rel, err := filepath.Rel(r.Root, p.Path); err == nil && rel != "." {
				label = fmt.Sprintf("%s (%s)", p.Name, filepath.ToSlash(rel))
			} else {
				label = p.Path
			}
		}
		out[p.Path] = label
	}
	return out
}

// Note prints an advisory line about the scan itself, such as a skipped symlink.
func (t *Terminal) Note(format string, args ...any) {
	if t.quiet {
		return
	}
	fmt.Fprintf(t.w, "%s %s\n",
		t.style.paint(colDim, t.style.glyph("·", "-")),
		fmt.Sprintf(format, args...))
}

func hasErrors(p *model.Project) bool { return len(p.Errors) > 0 }

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func pluralY(n int) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}

func humanMillis(ms int64) string {
	if ms < 1000 {
		return fmt.Sprintf("%dms", ms)
	}
	return fmt.Sprintf("%.1fs", float64(ms)/1000)
}
