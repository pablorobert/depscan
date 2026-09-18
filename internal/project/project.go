// Package project parses a project's package.json and joins it with its lockfile.
package project

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/pablorobert/depscan/internal/bunfig"
	"github.com/pablorobert/depscan/internal/lockfile"
	"github.com/pablorobert/depscan/internal/model"
)

// packageJSON is the subset of a package.json depscan reads.
type packageJSON struct {
	Name                 string            `json:"name"`
	Version              string            `json:"version"`
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	// Workspaces is either an array of globs or an object with a "packages" array.
	Workspaces json.RawMessage `json:"workspaces"`
}

// LoadOptions controls how a project is loaded.
type LoadOptions struct {
	AllowBunSpawn       bool
	SpawnTimeoutSeconds int
	// GlobalBunfig is the user-wide bunfig.toml consulted after the project's own for
	// minimumReleaseAge. Empty skips it, which keeps tests independent of the machine.
	GlobalBunfig string
}

// Load reads dir's package.json and lockfile and returns a project whose dependency
// set is resolved. Failures are recorded on the project rather than returned, so a
// single broken project never aborts the scan; only an unreadable package.json makes
// the project unusable, and even then a project is returned.
func Load(dir string, opts LoadOptions) *model.Project {
	p := &model.Project{
		Path:           dir,
		Name:           filepath.Base(dir),
		PackageManager: "unknown",
	}

	raw, err := os.ReadFile(filepath.Join(dir, "package.json"))
	if err != nil {
		p.AddError(model.ErrParsePackageJSON, model.PhaseDiscovery,
			fmt.Sprintf("package.json could not be read: %v", err))
		p.Outdated.Status = model.StatusError
		p.Security.Status = model.StatusError
		return p
	}

	var pkg packageJSON
	if err := json.Unmarshal(raw, &pkg); err != nil {
		p.AddError(model.ErrParsePackageJSON, model.PhaseDiscovery,
			fmt.Sprintf("package.json could not be parsed: %v", err))
		p.Outdated.Status = model.StatusError
		p.Security.Status = model.StatusError
		return p
	}
	if pkg.Name != "" {
		p.Name = pkg.Name
	}

	declared := declaredDeps(pkg)

	kind := lockfile.Detect(dir)
	p.PackageManager = kind.Manager()
	p.Lockfile = string(kind)

	res, err := lockfile.Parse(dir, declared, lockfile.ParseOptions{
		AllowBunSpawn:       opts.AllowBunSpawn,
		SpawnTimeoutSeconds: opts.SpawnTimeoutSeconds,
	})
	if err != nil {
		kindOfErr := model.ErrParseLockfile
		msg := err.Error()
		switch {
		case errors.Is(err, lockfile.ErrNoLockfile):
			kindOfErr = model.ErrNoLockfile
			msg = "no lockfile found; installed versions are unknown"
		case kind == lockfile.KindBunBin:
			kindOfErr = model.ErrBinaryLockfileNoBun
		}
		p.AddError(kindOfErr, model.PhaseLockfile, msg)
		p.Outdated.Status = model.StatusError
		p.Security.Status = model.StatusError
		return p
	}

	p.Deps = res.Deps

	// Only bun's window is read; npm, pnpm and yarn have equivalents that depscan does
	// not interpret yet, and for them the field stays null.
	if p.PackageManager == "bun" {
		policy, err := bunfig.Load(dir, opts.GlobalBunfig)
		if err != nil {
			p.AddError(model.ErrInternal, model.PhaseDiscovery,
				fmt.Sprintf("bunfig.toml could not be read; minimumReleaseAge ignored: %v", err))
		} else if policy != nil {
			p.MinimumReleaseAge = &model.MinimumReleaseAge{
				Seconds:  policy.Seconds,
				Excludes: policy.Excludes,
				Source:   policy.Source,
			}
			if p.MinimumReleaseAge.Excludes == nil {
				p.MinimumReleaseAge.Excludes = []string{}
			}
		}
	}
	return p
}

// declaredDeps flattens the four dependency sections, keeping the section each entry
// came from. Later sections do not overwrite earlier ones: a package listed in both
// dependencies and devDependencies is a runtime dependency.
func declaredDeps(pkg packageJSON) map[string]lockfile.Declared {
	out := make(map[string]lockfile.Declared)
	sections := []struct {
		deps     map[string]string
		category model.Category
	}{
		{pkg.Dependencies, model.CategoryProd},
		{pkg.DevDependencies, model.CategoryDev},
		{pkg.PeerDependencies, model.CategoryPeer},
		{pkg.OptionalDependencies, model.CategoryOptional},
	}
	for _, s := range sections {
		for name, rng := range s.deps {
			if _, exists := out[name]; exists {
				continue
			}
			out[name] = lockfile.Declared{Range: rng, Category: s.category}
		}
	}
	return out
}

// IsWorkspaceRoot reports whether dir's package.json declares workspaces. Workspace
// members are still discovered as independent projects; the marker only lets a
// consumer group them.
func IsWorkspaceRoot(dir string) bool {
	raw, err := os.ReadFile(filepath.Join(dir, "package.json"))
	if err != nil {
		return false
	}
	var pkg packageJSON
	if err := json.Unmarshal(raw, &pkg); err != nil {
		return false
	}
	return len(pkg.Workspaces) > 0 && string(pkg.Workspaces) != "null"
}
