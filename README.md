# depscan

Fast, read-only CLI that scans a directory of JavaScript/TypeScript projects and
reports which dependencies are outdated or vulnerable.

```text
$ depscan ~/projects

depscan

Scanning /home/user/projects ...

Found 12 projects

✓ my-game
    dependencies up to date

⚠ cadencia
    3 outdated
      vite                     5.0.0 → 5.4.21   minor
      eslint                   9.32.0 → 9.35.0  minor
      react                    18.2.0 → 19.2.0  major  (wanted not computed — use --wanted)

✗ foradacurva
    7 outdated
    3 affected packages

      direct
        axios                    HIGH       29 advisories   1.6.0 → 1.18.0
        vite                     MODERATE   17 advisories   fix unknown

      transitive
        esbuild                  MODERATE   1 advisory      0.21.5 → 0.25.0

⚠ legacy-project
    outdated: could not be determined
    no_lockfile: no lockfile found; installed versions are unknown

──────────────────────────────────────
Projects:            12
Fully analyzed:      10
Outdated packages:   14
Affected packages:   3   (advisories: 47)
Not checked:         1
With errors:         1

Completed in 2.4s
```

## What it does

Point it at a directory. It finds every `package.json`, reads each project's lockfile
to learn which versions are actually installed, then asks the npm registry what is
newer and what is vulnerable.

It does **not** invoke bun, npm, pnpm or yarn to gather data. It parses lockfiles and
talks to the registry itself, which makes it faster, deterministic, and independent of
whatever package managers happen to be installed. The one exception is a legacy binary
`bun.lockb`, described under [Supported package managers](#supported-package-managers).

**depscan never modifies a scanned project.** No installs, no lockfile rewrites, no
`node_modules` changes. The test suite fingerprints the whole tree before and after a
full scan and fails if a single byte differs.

## Honesty about what it does not know

This is the tool's central rule, and it shapes the output, the JSON and the exit codes.
Every analysis axis carries an explicit status:

| Status | Meaning |
|---|---|
| `clean` | checked, nothing found |
| `findings` | checked, something found |
| `not_checked` | deliberately not checked (`--offline`, `--only-*`, cold cache) |
| `error` | tried to check and failed (network, unreadable lockfile, timeout) |

"Zero vulnerabilities" and "I could not reach the advisory database" are completely
different answers, and depscan never conflates them. An empty result list means
nothing on its own — read the status.

## Installation

```bash
go install depscan@latest
```

Or build from a checkout:

```bash
go build -o depscan .
```

A single native binary, no runtime dependency on Node.js. Linux, macOS and Windows.

## Usage

```bash
depscan <directory>                 # human-readable report
depscan --json <directory>          # JSON on stdout, logs on stderr
depscan --quiet <directory>         # final result only, no progress
depscan --offline <directory>       # no network at all
depscan --wanted <directory>        # also compute the highest in-range version
depscan --only-vulnerable ~/code    # skip the outdated check
depscan --fail-on high ~/code       # exit 1 only at high or critical
```

`depscan --help` documents every flag, the output modes, the exit codes and the
supported package managers.

### The three versions

An outdated entry distinguishes three things that are easy to confuse:

```text
declared: ^1.6.0      the range in package.json
current:  1.6.0       what the lockfile resolved — what is in use
wanted:   1.18.0      the highest version satisfying `declared`
latest:   1.20.0      the registry's `latest` dist-tag
```

`updateType` classifies `current → wanted`, the jump you can take without touching
your range. `latestUpdateType` classifies `current → latest`, the real distance to the
newest release.

`latest` costs 79 bytes per package. The full version list needed to compute `wanted`
costs about 54 KB, so `wanted` is computed in two tiers and its provenance is always
recorded in `wantedSource`:

| `wantedSource` | When | Cost |
|---|---|---|
| `equals-latest` | `latest` satisfies `declared`, so `wanted == latest` by local proof | free |
| `registry` | `latest` is out of range and `--wanted` was passed | one request |
| `not-computed` | `latest` is out of range and `--wanted` was not passed | free |

With `not-computed`, `wanted` is `null`. That is the honest answer, not a claim that
the package is current.

### Offline

```bash
depscan --offline ~/projects
```

Makes zero requests. Anything the cache can answer is answered; everything else comes
back as `not_checked` with a `cache_miss_offline` error, never as a clean result.

## JSON output

`--json` writes exactly one JSON document to stdout. Progress, warnings and diagnostics
go to stderr, so `depscan --json . | jq` works.

```json
{
  "root": "/home/user/projects",
  "depscanVersion": "0.1.0",
  "startedAt": "2026-09-12T14:03:11Z",
  "durationMs": 2412,
  "options": { "offline": false, "wanted": false, "cache": true },
  "projects": [
    {
      "path": "/home/user/projects/cadencia",
      "name": "cadencia",
      "packageManager": "bun",
      "lockfile": "bun.lock",
      "workspaceRoot": null,
      "outdated": {
        "status": "findings",
        "packages": [
          {
            "name": "axios",
            "declared": "^1.6.0",
            "current": "1.6.0",
            "wanted": "1.18.0",
            "latest": "1.20.0",
            "updateType": "minor",
            "latestUpdateType": "major",
            "wantedSource": "registry",
            "direct": true,
            "category": "dependency"
          }
        ]
      },
      "security": {
        "status": "findings",
        "packages": [
          {
            "name": "axios",
            "installedVersion": "1.6.0",
            "maxSeverity": "high",
            "direct": true,
            "category": "dependency",
            "fixedVersion": "1.18.0",
            "fixedVersionInferred": true,
            "advisories": [
              {
                "id": 1111035,
                "url": "https://github.com/advisories/GHSA-jr5f-v2jv-69x6",
                "title": "axios Requests Vulnerable To Possible SSRF and Credential Leakage via Absolute URL",
                "severity": "high",
                "vulnerableVersions": ">=1.0.0 <1.8.2",
                "cwe": ["CWE-918"],
                "cvss": { "score": 0, "vectorString": null }
              }
            ]
          }
        ]
      },
      "errors": []
    }
  ],
  "summary": {
    "projects": 12,
    "fullyAnalyzed": 10,
    "outdatedPackages": 14,
    "vulnerablePackages": 3,
    "advisories": 47,
    "bySeverity": { "critical": 0, "high": 1, "moderate": 2, "low": 0, "unknown": 0 },
    "byUpdateType": { "patch": 6, "minor": 5, "major": 3, "unknown": 0 },
    "projectsNotChecked": 1,
    "projectsWithErrors": 1
  }
}
```

Notes on the schema:

- `summary.vulnerablePackages` counts **affected packages**; `summary.advisories`
  counts advisories. One package routinely carries dozens (axios alone had 29 at the
  time of writing), so the package count is the number meant for humans.
- `direct` and `category` are independent. `category` is the `package.json` section
  (`dependency`, `devDependency`, `peerDependency`, `optionalDependency`); a transitive
  dependency has `direct: false` and `category: null`. `transitive` is never a category.
- `fixedVersion` is **derived**, not reported by the registry: it is the upper bound of
  the vulnerable range. When the range has an inclusive or absent upper bound the field
  is `null` rather than a guess. `fixedVersionInferred` marks the derivation.
- `errors[].kind` is a closed enum: `no_lockfile`, `binary_lockfile_no_bun`,
  `parse_package_json`, `parse_lockfile`, `unsupported_lockfile_version`, `network`,
  `timeout`, `cache_miss_offline`, `internal`. `errors[].phase` is `discovery`,
  `lockfile`, `outdated` or `security`.
- The schema is versioned by `depscanVersion`.

## Exit codes

```text
0  all checks completed, nothing found
1  findings at or above the threshold
2  operational error (bad argument, unreadable root, internal failure)
3  nothing found, but one or more checks were left incomplete
```

Precedence is `2 > 1 > 3 > 0`, so code `3` only appears when there was nothing to fail
on. By default any vulnerability produces `1`; an outdated dependency does not, because
an available patch release should not redden a build forever. Raise the bar with
`--fail-on high`, or opt in with `--fail-on-outdated`.

## Supported package managers

| Manager | Lockfiles |
|---|---|
| bun | `bun.lock` (JSONC), `bun.lockb` (binary — see below) |
| npm | `package-lock.json` v1, v2, v3 |
| pnpm | `pnpm-lock.yaml` 6.0 and 9.0 |
| yarn | `yarn.lock` for Yarn 1 and for Yarn 2+ (berry) |

When several lockfiles coexist, bun wins and npm loses, because a stale
`package-lock.json` is the most common leftover of a migration.

A binary `bun.lockb` cannot be parsed. If `bun` is on `PATH`, depscan runs
`bun pm ls --all` **once for that project** — never once per dependency — and parses
the tree. Without bun, that project reports a `binary_lockfile_no_bun` error and the
scan continues. The fallback lives entirely inside the bun adapter; nothing else in
depscan knows a package manager exists.

## Cache

Responses are cached in `os.UserCacheDir()/depscan/`, split into `registry/` and
`advisories/`, with a 6-hour TTL. Packuments also carry an `ETag`, so a stale entry is
revalidated with `If-None-Match` instead of re-downloaded. Writes are atomic, so
concurrent depscan runs cannot corrupt each other, and a corrupt entry is treated as a
miss and removed.

The cache never touches the scanned project. `--no-cache` bypasses it for one run.

## Performance

The scan runs in three phases, and phase 2 is the reason it is fast: 100 projects share
most of their dependencies, so network work is batched **per unique package**, never per
project.

```text
phase 1  walk, parse package.json + lockfile          local, parallel, no network
phase 2  1 bulk advisory POST + N dist-tags requests  batched by unique package
phase 3  join the answers back onto the projects      local
```

Measured against the live registry for a set of ~1700 unique packages:

| Step | Cost |
|---|---|
| walk + parse 100 lockfiles (~3 MB) | ~100 ms |
| advisories, one POST covering 1708 packages | ~400 ms |
| `latest` via dist-tags, 79 bytes each | ~100–167 packages/s |
| `wanted` via packument, ~54 KB each | ~8 packages/s (hence opt-in) |

For roughly 100 projects: about 11–17 s cold without `--wanted`, under a second with a
warm cache. `--wanted` adds roughly 48 s on that set, which is why it is a flag.

## Limitations

- Outdated reporting covers **direct** dependencies only; bumping a transitive version
  is not something a project can do directly. Vulnerability scanning covers the entire
  lockfile, transitive dependencies included.
- Workspace members are discovered as independent projects and tagged with
  `workspaceRoot`. Dependency relationships between workspace packages are not resolved.
- `fixedVersion` is inferred from the vulnerable range, not reported by the registry.
- npm is the only advisory source. Packages from other registries are not covered.
- Directory symlinks are not followed, which avoids cycles but also skips projects that
  are only reachable through one.
- A project with no lockfile reports an error: without one, no installed version can be
  known, and depscan will not guess from a declared range.

## Development

```bash
go build ./...
go test ./...          # 140 tests, no network access required
go test ./... -race    # needs cgo and a C toolchain
go vet ./...
gofmt -l .
```

The suite covers all six lockfile adapters, semver classification, the `wantedSource`
tiers, `fixedVersion` inference including the cases that must return `null`, the
tri-state transitions, exit-code precedence, cache TTL/ETag/corruption handling, and
HTTP behaviour (200, 304, 404, 5xx with retry, timeout, malformed body) against a local
test server. `testdata/fixtures/` holds the integration fixtures.

The race detector needs `CGO_ENABLED=1` and a C compiler. It has been run clean on
both linux/amd64 (gcc 15, including `-count=5` over the concurrent packages) and
windows/amd64 (mingw-w64 UCRT gcc 16). The product itself needs no C toolchain: the
binary is pure Go and cross-compiles to all three platforms with cgo disabled.

Two tests are conditional:

- `TestWalkDoesNotFollowSymlinkCycle` skips on Windows, where creating a directory
  symlink needs elevation. It runs on Linux and macOS.
- The `bun.lockb` tests skip when `bun` is not on `PATH`, since that is the one path
  that shells out. The binary fixture was produced with a `bunfig.toml` carrying
  `[install] saveTextLockfile = false`, which is the only way to get a binary lockfile
  out of a current bun; that file is committed beside it to document the regeneration.

See `SPEC.md` for the design, the decisions behind it, and the full measurement appendix.
