# depscan

Fast CLI tool for scanning JavaScript/TypeScript projects and reporting outdated and vulnerable dependencies.

## 1. Goal

Build a fast, lightweight CLI that recursively scans a directory for JavaScript/TypeScript projects and reports dependency updates and security vulnerabilities.

The primary use case is:

> "I have a directory containing many JS/TS projects. Tell me which projects have outdated or vulnerable dependencies without making me inspect each project manually."

The tool should be particularly useful for developers who maintain multiple projects and for AI coding agents that need a compact, machine-readable dependency overview.

The project should prioritize:

- speed
- simplicity
- read-only operation by default
- useful terminal output
- JSON output for automation/AI agents
- zero configuration for common cases

---

# 2. Non-goals for v1

Do NOT implement these in the MVP:

- automatically updating dependencies
- modifying package.json
- modifying lockfiles
- installing dependencies
- deleting node_modules
- dependency graph visualization
- AI/LLM integration
- web UI
- daemon/server mode
- package publishing
- license compliance analysis
- abandoned-package detection
- code analysis
- AST parsing

These may be considered later.

The MVP should remain a small and reliable CLI.

---

# 3. Target platforms

The application should run on:

- Linux
- macOS
- Windows

It should preferably be distributed as a single native executable.

---

# 4. Technology

Choose either Go or Rust.

Preference:

- Go is acceptable/preferred if it significantly reduces implementation complexity.
- Rust is also acceptable if there is a strong ecosystem/library advantage.

Avoid unnecessary frameworks.

The resulting binary should have no runtime dependency on Node.js.

---

# 5. Basic usage

The primary command should be:

```bash
depscan <directory>
```

Example:

```bash
depscan ~/projects
```

The tool recursively searches the supplied directory for JavaScript/TypeScript projects.

Example output:

```text
depscan

Scanning ~/projects ...

Found 12 projects

PROJECT             OUTDATED    VULNERABILITIES

cadencia             3           0
foradacurva          7           1
my-game              0           0
website              4           2

Summary
──────────────────────────────
Projects:             12
Outdated packages:    14
Vulnerabilities:       3

Done in 1.8s
```

Output formatting should be concise and easy to scan.

---

# 6. Project discovery

A project is identified primarily by the presence of:

```text
package.json
```

The scanner must search recursively.

Example:

```text
projects/
├── app-a/
│   ├── package.json
│   └── node_modules/
├── app-b/
│   ├── package.json
│   └── node_modules/
└── company/
    ├── frontend/
    │   └── package.json
    └── backend/
        └── package.json
```

All four package.json files should be independently detectable.

The tool must NOT assume that the root directory is itself a project.

---

# 7. Directory traversal

The scanner must avoid recursively traversing directories that are known to contain huge amounts of irrelevant data.

At minimum ignore:

```text
node_modules
.git
```

The scanner must still detect a project's `package.json` even when that project contains a `node_modules` directory.

Example:

```text
project/
├── package.json       <-- detect this
├── node_modules/      <-- do not traverse
└── src/
```

Other common directories may be ignored when appropriate, but avoid creating an unnecessarily aggressive exclusion list.

The user should eventually be able to override exclusions, but this is not required for v1.

---

# 8. Package manager detection

Determine the package manager from lockfiles and/or project metadata.

Support at minimum:

```text
bun
npm
pnpm
yarn
```

Recognize:

```text
bun.lock
bun.lockb
package-lock.json
pnpm-lock.yaml
yarn.lock
```

When possible, prefer the package manager indicated by the lockfile.

Example:

```text
package.json
bun.lock
```

→ Bun

```text
package.json
package-lock.json
```

→ npm

If no lockfile exists, report:

```text
package manager: unknown
```

Do not guess unnecessarily.

---

# 9. Dependency categories

Read dependencies from `package.json`:

```json
{
  "dependencies": {},
  "devDependencies": {},
  "peerDependencies": {},
  "optionalDependencies": {}
}
```

At minimum, analyze:

- dependencies
- devDependencies

The tool should preserve the category in its internal model.

Example:

```text
vite       devDependency
react      dependency
```

---

# 10. Outdated dependency detection

The tool should determine whether installed/project dependencies have newer versions available.

The implementation should prefer native package-manager capabilities where practical.

Examples:

Bun:

```bash
bun outdated
```

npm:

```bash
npm outdated
```

pnpm:

```bash
pnpm outdated
```

Yarn:

Use the appropriate supported command for the detected Yarn version.

IMPORTANT:

The tool is READ-ONLY.

It must not perform:

```text
install
update
upgrade
add
remove
```

or modify any project files.

If invoking package-manager commands, use them strictly for inspection.

---

# 11. Version classification

When an update is available, classify it as:

```text
PATCH
MINOR
MAJOR
```

Example:

```text
vite 7.1.3 → 7.1.5     PATCH
eslint 9.32 → 9.35      MINOR
react 18.3 → 19.0       MAJOR
```

If semantic-version classification cannot be reliably determined, use:

```text
UNKNOWN
```

Do not invent classifications.

---

# 12. Security audit

The tool should support dependency vulnerability scanning.

Use the native package-manager audit functionality where possible.

Examples:

```bash
bun audit
npm audit
pnpm audit
```

Yarn support should follow the capabilities of the detected Yarn version.

The implementation should normalize audit results into a common internal representation.

Example:

```text
axios
  HIGH
  installed: 1.6.0
  fixed:     1.6.8
```

The exact wording of native package-manager output must NOT leak into the core data model.

---

# 13. Severity

Normalize vulnerabilities into:

```text
CRITICAL
HIGH
MODERATE
LOW
UNKNOWN
```

The tool should preserve the original severity when available.

---

# 14. Terminal output

Human-readable output is the default.

Example:

```text
$ depscan ~/projects

Scanning 12 projects...

✓ my-game
    dependencies up to date

⚠ cadencia
    3 outdated
      vite       7.1.3 → 7.1.5   patch
      eslint     9.32 → 9.35     minor
      react      18.3 → 19.0     major

✗ foradacurva
    7 outdated
    1 vulnerability
      axios      HIGH

──────────────────────────────────────
Projects:          12
Outdated:          14
Vulnerabilities:    3

Completed in 1.8s
```

The exact visual design can be decided during implementation.

Use color only as a visual enhancement.

The output must remain understandable when color is disabled.

---

# 15. JSON output

Support:

```bash
depscan --json <directory>
```

The output must be valid JSON and contain no human-readable log messages on stdout.

Example:

```json
{
  "root": "/home/user/projects",
  "projects": [
    {
      "path": "/home/user/projects/cadencia",
      "packageManager": "bun",
      "outdated": [
        {
          "name": "vite",
          "current": "7.1.3",
          "latest": "7.1.5",
          "type": "patch",
          "category": "devDependency"
        }
      ],
      "vulnerabilities": []
    }
  ],
  "summary": {
    "projects": 12,
    "outdated": 14,
    "vulnerabilities": 3
  }
}
```

The JSON schema should be documented.

This output is important because a future AI coding agent should be able to consume depscan without parsing terminal output.

---

# 16. Filtering

Support at least:

```bash
depscan --only-outdated <directory>
```

and:

```bash
depscan --only-vulnerable <directory>
```

If neither option is supplied, show both.

Also support filtering by package manager if practical:

```bash
depscan --manager bun <directory>
```

This is optional for the MVP if it complicates the CLI unnecessarily.

---

# 17. Performance

Performance is an important project goal.

The tool should:

- traverse directories concurrently where appropriate
- avoid traversing node_modules
- avoid reading unnecessary files
- avoid spawning processes unnecessarily
- process independent projects concurrently where safe

However, correctness is more important than micro-optimizations.

The benchmark target for a directory containing approximately:

```text
100 projects
```

should be reasonable on a normal developer machine.

The tool should display total execution time.

---

# 18. External commands

Package managers are external processes.

The implementation should:

- locate the executable
- verify that it exists
- invoke it safely without shell interpolation
- capture stdout/stderr
- enforce a reasonable timeout
- handle non-zero exit codes
- continue scanning other projects when one project fails

A broken/missing package manager in one project must not abort the entire scan.

Example:

```text
⚠ project-x
  Could not run bun: executable not found
```

The final summary should still include the other projects.

---

# 19. Error handling

Errors should be associated with the affected project.

Do not fail the complete scan because:

- package.json is malformed
- lockfile is malformed
- package manager is missing
- audit command fails
- network access is unavailable
- a project has an unsupported configuration

Example:

```text
⚠ legacy-project
  package.json could not be parsed

⚠ old-project
  npm audit failed

12 projects scanned
10 successfully analyzed
2 with errors
```

---

# 20. Network behavior

Dependency update and vulnerability information may require network access.

The tool should clearly distinguish:

```text
analysis successful
```

from:

```text
unable to obtain remote dependency information
```

Do not silently treat a network failure as "everything is up to date".

Example:

```text
⚠ project-a
  Could not check outdated packages: network unavailable
```

---

# 21. Exit codes

Define useful exit codes.

Suggested behavior:

```text
0 = scan completed successfully, no problems detected
1 = scan completed and outdated dependencies and/or vulnerabilities were found
2 = operational/configuration error
```

The exact convention can be adjusted during implementation, but it must be documented.

This makes the tool useful in CI and automation.

---

# 22. CI-friendly mode

Support:

```bash
depscan --quiet <directory>
```

This should suppress progress output and produce only the final result.

JSON mode should also be suitable for CI.

Potential future option:

```bash
depscan --fail-on high
```

Do NOT implement this unless it is trivial.

---

# 23. Configuration

No configuration file is required for v1.

The tool should work immediately after installation.

Future configuration may include:

```text
.depscan.toml
```

but this should not be implemented in the MVP unless required by the implementation.

---

# 24. Architecture

Keep the implementation modular.

Suggested conceptual modules:

```text
scanner
    directory traversal
    project discovery

project
    package.json parsing
    package manager detection

manager
    bun
    npm
    pnpm
    yarn

outdated
    normalized outdated dependency model

audit
    normalized vulnerability model

output
    terminal formatter
    JSON formatter

cli
    argument parsing
    exit codes
```

Do not over-engineer this.

Interfaces should only be introduced where they provide a clear benefit.

---

# 25. Internal data model

The implementation should have a normalized representation independent of the package manager.

Conceptually:

```text
Project
 ├── path
 ├── packageManager
 ├── dependencies
 ├── outdated
 ├── vulnerabilities
 └── errors
```

Dependency:

```text
Dependency
 ├── name
 ├── current
 ├── latest
 ├── updateType
 └── category
```

Vulnerability:

```text
Vulnerability
 ├── package
 ├── severity
 ├── installedVersion
 ├── fixedVersion
 ├── advisory
 └── description
```

The actual implementation may add fields as required by the supported package managers.

---

# 26. Testing

Tests are required.

At minimum:

### Unit tests

- package.json parsing
- dependency extraction
- package-manager detection
- semver classification
- JSON serialization
- directory filtering
- error handling

### Integration tests

Use fixtures representing:

```text
bun project
npm project
pnpm project
yarn project
project without lockfile
project with malformed package.json
nested projects
project containing node_modules
```

Avoid making the test suite depend on live internet services.

External package-manager commands should be mockable or tested through controlled fixtures where practical.

---

# 27. CLI help

The following should work:

```bash
depscan --help
depscan --version
```

Help should clearly document:

```text
usage
options
output modes
exit codes
supported package managers
```

---

# 28. README

Create a concise README containing:

- what depscan does
- installation
- basic usage
- example output
- JSON usage
- supported package managers
- limitations
- development instructions

Keep the README practical rather than marketing-heavy.

---

# 29. MVP acceptance criteria

The MVP is complete when all of the following are true:

- [ ] A directory can be recursively scanned.
- [ ] Multiple independent projects can be detected.
- [ ] `node_modules` and `.git` are not recursively traversed.
- [ ] package.json is parsed safely.
- [ ] Bun, npm, pnpm and Yarn are detected when possible.
- [ ] Outdated dependencies can be reported.
- [ ] Vulnerabilities can be reported.
- [ ] Updates are classified as patch/minor/major when possible.
- [ ] Human-readable terminal output exists.
- [ ] JSON output exists.
- [ ] The tool never modifies the scanned projects.
- [ ] One broken project does not abort the complete scan.
- [ ] Useful exit codes exist.
- [ ] Unit tests exist.
- [ ] Integration fixtures exist.
- [ ] README exists.
- [ ] `depscan --help` works.
- [ ] `depscan --version` works.

---

# 30. Future roadmap — DO NOT implement yet

These ideas should be kept in mind but excluded from the MVP.

### Dependency context for AI agents

```bash
depscan --context .
```

Example:

```text
12 projects

37 outdated dependencies

21 patch
12 minor
4 major

3 high vulnerabilities

Most affected projects:
...
```

The output would be optimized for AI consumption rather than humans.

### Dependency graph

```bash
depscan graph .
```

Potentially show:

```text
project
 └── package
      ├── dependency
      └── dependency
```

### Upgrade impact analysis

```bash
depscan impact react
```

### Workspace/monorepo awareness

Support:

```text
npm workspaces
pnpm workspaces
Yarn workspaces
Bun workspaces
```

with dependency relationships between packages.

### Dependency age

Report how old the currently used version is.

### Deprecated packages

Detect packages marked deprecated.

### License analysis

Analyze dependency licenses.

### Automatic fixes

Potential future commands:

```bash
depscan update
depscan fix
```

These must be explicitly opt-in and should never be part of the current read-only scanner.

---

# 31. Design principle

The most important principle of depscan is:

> **Do one thing very well: quickly tell me what is wrong with the dependencies across all my JS/TS projects.**

It should be:

```text
fast
small
read-only
predictable
scriptable
agent-friendly
```

Avoid turning the project into a general-purpose JavaScript package manager.

The first release should feel like a Unix utility: install it, point it at a directory, and immediately get useful information.
