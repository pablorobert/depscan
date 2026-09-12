// depscan reports outdated and vulnerable dependencies across JavaScript and
// TypeScript projects. It is read-only: it parses lockfiles and queries the npm
// registry directly, and never invokes a package manager to fetch data.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/pablorobert/depscan/internal/cli"
)

func main() {
	cfg, err := cli.Parse(os.Args[1:], os.Stderr)
	if err != nil {
		// flag already printed its own message and the usage text.
		if !errors.Is(err, flag.ErrHelp) {
			fmt.Fprintf(os.Stderr, "depscan: %v\n", err)
		}
		os.Exit(cli.ExitOperational)
	}

	switch {
	case cfg.ShowHelp:
		cli.Usage(os.Stdout)
		os.Exit(cli.ExitOK)
	case cfg.ShowVersion:
		fmt.Fprintf(os.Stdout, "depscan %s\n", cli.Version)
		os.Exit(cli.ExitOK)
	case cfg.ListCache:
		os.Exit(cli.ListCache(os.Stdout, os.Stderr))
	case cfg.CleanCache:
		os.Exit(cli.CleanCache(os.Stdout, os.Stderr))
	}

	os.Exit(cli.Run(cfg, os.Stdout, os.Stderr))
}
