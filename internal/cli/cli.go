// Package cli parses arguments, drives a scan and maps the result to an exit code.
package cli

import (
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/pablorobert/depscan/internal/model"
)

// Version is the depscan release, reported by --version and embedded in JSON output.
const Version = "0.1.0"

// Exit codes. SPEC.md section 14. Precedence is 2 > 1 > 3 > 0, so code 3 only ever
// appears when there were no findings to fail on.
const (
	ExitOK          = 0
	ExitFindings    = 1
	ExitOperational = 2
	ExitIncomplete  = 3
)

// Config is a parsed command line.
type Config struct {
	Root string

	JSON  bool
	Quiet bool

	OnlyOutdated   bool
	OnlyVulnerable bool
	DirectOnly     bool
	Manager        string

	Wanted bool

	Offline     bool
	NoCache     bool
	CacheList   bool
	CacheClean  bool
	Concurrency int
	Timeout     time.Duration

	FailOn         model.Severity
	FailOnOutdated bool
	Ignore         map[string]bool

	ShowHelp    bool
	ShowVersion bool

	// RegistryBaseURL and AdvisoryBaseURL override the public npm endpoints. They
	// have no flag: they exist so the test suite can run against a local server and
	// so a future --registry flag has somewhere to land.
	RegistryBaseURL string
	AdvisoryBaseURL string
}

// usageText documents everything --help promises: usage, options, output modes, exit
// codes and supported package managers.
const usageText = `depscan ` + Version + ` — report outdated and vulnerable dependencies across JS/TS projects

USAGE
  depscan [flags] <directory>

  Walks <directory> recursively, finds every package.json, reads each project's
  lockfile and reports what is outdated or vulnerable. Read-only: depscan never
  modifies a scanned project.

OUTPUT
  --json                 emit JSON on stdout; logs and progress go to stderr
  --quiet                suppress progress, keep the final result

SCOPE
  --only-outdated        check updates only; security reports "not_checked"
  --only-vulnerable      check advisories only; outdated reports "not_checked"
  --direct-only          display direct dependencies only (JSON keeps transitives)
  --manager <pm>         only projects using this package manager
                         (bun, npm, pnpm, yarn, unknown)

DEPTH
  --wanted               also compute the highest in-range version for packages
                         whose latest release falls outside the declared range.
                         Costs one registry document per such package, so it is
                         off by default; without it those entries report
                         wantedSource "not-computed" rather than claiming to be
                         up to date.

NETWORK
  --offline              make no network requests; uses the cache and reports
                         "not_checked" for whatever it cannot answer
  --no-cache             ignore the on-disk cache for this run
  --concurrency <n>      concurrent registry requests (default 64, max 256)
  --timeout <duration>   per-request timeout (default 15s)

CACHE
  --cache-list           show where the cache lives, what it holds and which
                         entries are the heaviest, then exit
  --cache-clean          delete the cache and report what was freed, then exit

  Both take no directory. The cache is only ever a copy of something the
  registry can serve again, so deleting it is always safe; the next run just
  pays the cold price again.

EXIT
  --fail-on <severity>   minimum severity that causes exit 1
                         (low, moderate, high, critical)
  --fail-on-outdated     let outdated dependencies cause exit 1 as well
  --ignore <id>          ignore one advisory, by GHSA id or numeric id (repeatable)

  --help                 show this help
  --version              show the version

OUTPUT MODES
  Human-readable by default; --json for automation. JSON output is a single
  document on stdout with no log lines mixed in. Every analysis axis carries an
  explicit status: "clean", "findings", "not_checked" or "error". An empty result
  never means "verified clean" unless the status says so.

EXIT CODES
  0  all checks completed, nothing found
  1  findings at or above the threshold
  2  operational error (bad argument, unreadable root, internal failure)
  3  nothing found, but one or more checks were left incomplete

SUPPORTED PACKAGE MANAGERS
  bun    bun.lock, bun.lockb (via a single "bun pm ls" call when bun is installed)
  npm    package-lock.json (lockfileVersion 1, 2, 3)
  pnpm   pnpm-lock.yaml (6.0, 9.0)
  yarn   yarn.lock (Yarn 1 and Yarn 2+/berry)

  Package managers are read, never invoked to fetch data: depscan parses lockfiles
  and talks to the registry itself.
`

// ignoreList collects repeated --ignore flags.
type ignoreList struct {
	values map[string]bool
}

func (l *ignoreList) String() string {
	if l.values == nil {
		return ""
	}
	out := make([]string, 0, len(l.values))
	for v := range l.values {
		out = append(out, v)
	}
	return strings.Join(out, ",")
}

func (l *ignoreList) Set(v string) error {
	if l.values == nil {
		l.values = map[string]bool{}
	}
	for part := range strings.SplitSeq(v, ",") {
		if p := strings.TrimSpace(part); p != "" {
			l.values[p] = true
		}
	}
	return nil
}

// Parse reads the command line. Errors are returned rather than exiting so main can
// map them to exit code 2.
func Parse(args []string, stderr io.Writer) (*Config, error) {
	cfg := &Config{}
	var failOn string
	ignores := &ignoreList{}

	fs := flag.NewFlagSet("depscan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, usageText) }

	fs.BoolVar(&cfg.JSON, "json", false, "emit JSON on stdout")
	fs.BoolVar(&cfg.Quiet, "quiet", false, "suppress progress output")
	fs.BoolVar(&cfg.OnlyOutdated, "only-outdated", false, "check updates only")
	fs.BoolVar(&cfg.OnlyVulnerable, "only-vulnerable", false, "check advisories only")
	fs.BoolVar(&cfg.DirectOnly, "direct-only", false, "display direct dependencies only")
	fs.StringVar(&cfg.Manager, "manager", "", "only projects using this package manager")
	fs.BoolVar(&cfg.Wanted, "wanted", false, "compute the highest in-range version")
	fs.BoolVar(&cfg.Offline, "offline", false, "make no network requests")
	fs.BoolVar(&cfg.NoCache, "no-cache", false, "ignore the on-disk cache")
	fs.BoolVar(&cfg.CacheList, "cache-list", false, "show what the cache holds and exit")
	fs.BoolVar(&cfg.CacheClean, "cache-clean", false, "delete the cache and exit")
	fs.IntVar(&cfg.Concurrency, "concurrency", 64, "concurrent registry requests")
	fs.DurationVar(&cfg.Timeout, "timeout", 15*time.Second, "per-request timeout")
	fs.StringVar(&failOn, "fail-on", "", "minimum severity for exit 1")
	fs.BoolVar(&cfg.FailOnOutdated, "fail-on-outdated", false, "outdated causes exit 1")
	fs.Var(ignores, "ignore", "ignore an advisory by id (repeatable)")
	fs.BoolVar(&cfg.ShowHelp, "help", false, "show help")
	fs.BoolVar(&cfg.ShowVersion, "version", false, "show version")

	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	// These act on depscan itself rather than on a directory, so they take no
	// positional argument.
	if cfg.ShowHelp || cfg.ShowVersion || cfg.CacheList || cfg.CacheClean {
		if cfg.CacheList && cfg.CacheClean {
			return nil, fmt.Errorf("--cache-list and --cache-clean are mutually exclusive")
		}
		if len(fs.Args()) > 0 {
			return nil, fmt.Errorf("this option takes no directory, got %q", fs.Args()[0])
		}
		return cfg, nil
	}

	rest := fs.Args()
	switch len(rest) {
	case 0:
		return nil, fmt.Errorf("no directory given\n\nusage: depscan [flags] <directory>\nrun 'depscan --help' for details")
	case 1:
		cfg.Root = rest[0]
	default:
		return nil, fmt.Errorf("expected exactly one directory, got %d", len(rest))
	}

	if cfg.OnlyOutdated && cfg.OnlyVulnerable {
		return nil, fmt.Errorf("--only-outdated and --only-vulnerable are mutually exclusive")
	}
	if cfg.Concurrency < 1 {
		return nil, fmt.Errorf("--concurrency must be at least 1")
	}
	if cfg.Concurrency > 256 {
		return nil, fmt.Errorf("--concurrency must not exceed 256")
	}
	if cfg.Timeout <= 0 {
		return nil, fmt.Errorf("--timeout must be positive")
	}
	if cfg.Manager != "" {
		switch cfg.Manager {
		case "bun", "npm", "pnpm", "yarn", "unknown":
		default:
			return nil, fmt.Errorf("unknown package manager %q (expected bun, npm, pnpm, yarn or unknown)", cfg.Manager)
		}
	}
	if failOn != "" {
		s := model.ParseSeverity(strings.ToLower(failOn))
		if s == model.SeverityUnknown {
			return nil, fmt.Errorf("unknown severity %q (expected low, moderate, high or critical)", failOn)
		}
		cfg.FailOn = s
	} else {
		// Default: any vulnerability is a finding. An outdated dependency is not,
		// unless --fail-on-outdated is given.
		cfg.FailOn = model.SeverityLow
	}
	cfg.Ignore = ignores.values

	return cfg, nil
}

// Usage writes the help text.
func Usage(w io.Writer) { fmt.Fprint(w, usageText) }

// ExitCode maps a finished report to a process exit code.
func ExitCode(r *model.Report, cfg *Config) int {
	if r.HasFindingsAtLeast(cfg.FailOn) {
		return ExitFindings
	}
	if cfg.FailOnOutdated && r.HasOutdated() {
		return ExitFindings
	}
	if r.AnyIncomplete() {
		return ExitIncomplete
	}
	return ExitOK
}
