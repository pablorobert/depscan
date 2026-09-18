package cli

import (
	"context"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/pablorobert/depscan/internal/advisory"
	"github.com/pablorobert/depscan/internal/bunfig"
	"github.com/pablorobert/depscan/internal/cache"
	"github.com/pablorobert/depscan/internal/model"
	"github.com/pablorobert/depscan/internal/output"
	"github.com/pablorobert/depscan/internal/project"
	"github.com/pablorobert/depscan/internal/registry"
	"github.com/pablorobert/depscan/internal/resolve"
	"github.com/pablorobert/depscan/internal/scanner"
)

// Run executes a scan and writes the report. It returns the process exit code.
func Run(cfg *Config, stdout, stderr io.Writer) int {
	started := time.Now()

	// In JSON mode stdout carries nothing but the document, so every human-facing
	// line goes to stderr instead.
	progressOut := stdout
	if cfg.JSON {
		progressOut = stderr
	}
	term := output.NewTerminal(progressOut, cfg.Quiet || cfg.JSON, cfg.DirectOnly)

	root, err := filepath.Abs(cfg.Root)
	if err != nil {
		fmt.Fprintf(stderr, "depscan: %v\n", err)
		return ExitOperational
	}
	term.Scanning(root)

	walk, err := scanner.Walk(root)
	if err != nil {
		fmt.Fprintf(stderr, "depscan: cannot scan %s: %v\n", root, err)
		return ExitOperational
	}
	for _, link := range walk.SkippedSymlinks {
		term.Note("skipped symlinked directory %s", link)
	}
	for _, bad := range walk.Unreadable {
		term.Note("could not read %s", bad)
	}

	projects := loadProjects(walk.Dirs)
	projects = applyWorkspaceTags(projects)
	if cfg.Manager != "" {
		projects = filterByManager(projects, cfg.Manager)
	}
	term.Found(len(projects))

	clients, cacheWarning := buildClients(cfg)
	if cacheWarning != nil {
		term.Note("cache unavailable (%v); continuing without it", cacheWarning)
	}

	ctx := context.Background()
	resolve.Run(ctx, projects, clients, resolve.Options{
		Wanted:         cfg.Wanted,
		SkipOutdated:   cfg.OnlyVulnerable,
		SkipVulnerable: cfg.OnlyOutdated,
		Ignore:         cfg.Ignore,
	})

	report := &model.Report{
		Root:           root,
		DepscanVersion: Version,
		StartedAt:      started.UTC().Format(time.RFC3339),
		Options: model.Options{
			Offline: cfg.Offline,
			Wanted:  cfg.Wanted,
			Cache:   !cfg.NoCache,
		},
		Projects: projects,
	}
	report.BuildSummary()
	report.DurationMs = time.Since(started).Milliseconds()

	if cfg.JSON {
		if err := output.WriteJSON(stdout, report); err != nil {
			fmt.Fprintf(stderr, "depscan: could not write JSON: %v\n", err)
			return ExitOperational
		}
	} else {
		term.Report(report)
	}

	return ExitCode(report, cfg)
}

// loadProjects reads every discovered project concurrently. Phase 1 is local work
// only: no network request is made here.
func loadProjects(dirs []string) []*model.Project {
	// The bun fallback for a binary bun.lockb is only possible when bun is on PATH.
	// Looking it up once keeps the adapter from probing per project.
	_, bunErr := exec.LookPath("bun")
	opts := project.LoadOptions{
		AllowBunSpawn:       bunErr == nil,
		SpawnTimeoutSeconds: 30,
		GlobalBunfig:        bunfig.GlobalPath(),
	}

	out := make([]*model.Project, len(dirs))
	workers := min(runtime.NumCPU()*2, len(dirs))
	if workers < 1 {
		return []*model.Project{}
	}

	jobs := make(chan int)
	var wg sync.WaitGroup
	for range workers {
		wg.Go(func() {
			for idx := range jobs {
				out[idx] = project.Load(dirs[idx], opts)
			}
		})
	}
	for i := range dirs {
		jobs <- i
	}
	close(jobs)
	wg.Wait()

	return out
}

// applyWorkspaceTags marks projects that sit under a workspace root. Workspace
// resolution itself is out of scope; the tag only lets a consumer group them.
func applyWorkspaceTags(projects []*model.Project) []*model.Project {
	roots := make(map[string]bool)
	for _, p := range projects {
		if project.IsWorkspaceRoot(p.Path) {
			roots[p.Path] = true
		}
	}
	if len(roots) == 0 {
		return projects
	}
	for _, p := range projects {
		if r := scanner.NearestWorkspaceRoot(p.Path, roots); r != "" {
			root := r
			p.WorkspaceRoot = &root
		}
	}
	return projects
}

func filterByManager(projects []*model.Project, manager string) []*model.Project {
	out := make([]*model.Project, 0, len(projects))
	for _, p := range projects {
		if p.PackageManager == manager {
			out = append(out, p)
		}
	}
	return out
}

// buildClients wires the network clients to the cache. A cache that cannot be opened
// degrades to no caching rather than failing the scan.
func buildClients(cfg *Config) (resolve.Clients, error) {
	c, cacheErr := cache.New(!cfg.NoCache)

	return resolve.Clients{
		Registry: registry.New(registry.Options{
			BaseURL:     cfg.RegistryBaseURL,
			Cache:       c,
			Offline:     cfg.Offline,
			Concurrency: cfg.Concurrency,
			Timeout:     cfg.Timeout,
		}),
		Advisory: advisory.New(advisory.Options{
			BaseURL: cfg.AdvisoryBaseURL,
			Cache:   c,
			Offline: cfg.Offline,
			Timeout: cfg.Timeout,
		}),
	}, cacheErr
}
