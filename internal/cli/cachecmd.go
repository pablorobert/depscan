package cli

import (
	"fmt"
	"io"

	"github.com/pablorobert/depscan/internal/cache"
)

// topCacheEntries is how many of the heaviest entries --list-cache names. A handful is
// enough to explain where the space went, which is the only reason to ask.
const topCacheEntries = 10

// ListCache prints what the cache currently holds.
func ListCache(stdout, stderr io.Writer) int {
	dir, err := cache.DefaultDir()
	if err != nil {
		fmt.Fprintf(stderr, "depscan: cannot locate the cache directory: %v\n", err)
		return ExitOperational
	}

	st, err := cache.Inspect(dir, topCacheEntries)
	if err != nil {
		fmt.Fprintf(stderr, "depscan: cannot read the cache: %v\n", err)
		return ExitOperational
	}

	fmt.Fprintf(stdout, "Cache directory\n  %s\n\n", st.Dir)
	// A directory that exists but holds nothing reads the same to a user as one that
	// was never created.
	if !st.Exists || st.Entries == 0 {
		fmt.Fprintln(stdout, "The cache is empty: nothing has been stored yet.")
		return ExitOK
	}

	fmt.Fprintf(stdout, "%d entries, %s\n", st.Entries, humanBytes(st.Bytes))
	if st.Unreadable > 0 {
		fmt.Fprintf(stdout, "%d entries could not be read\n", st.Unreadable)
	}

	if len(st.Buckets) > 0 {
		fmt.Fprintln(stdout)
		for _, b := range st.Buckets {
			fmt.Fprintf(stdout, "  %-12s %5d entries   %10s\n", b.Name, b.Entries, humanBytes(b.Bytes))
		}
	}

	if len(st.Largest) > 0 {
		fmt.Fprintf(stdout, "\nHeaviest entries\n")
		for _, e := range st.Largest {
			fmt.Fprintf(stdout, "  %10s  %s\n", humanBytes(e.Bytes), e.Key)
		}
	}

	fmt.Fprintf(stdout, "\nEntries expire after %s. Run 'depscan --clean-cache' to remove them now.\n", cache.TTL)
	return ExitOK
}

// CleanCache deletes the cache and reports what it freed.
func CleanCache(stdout, stderr io.Writer) int {
	dir, err := cache.DefaultDir()
	if err != nil {
		fmt.Fprintf(stderr, "depscan: cannot locate the cache directory: %v\n", err)
		return ExitOperational
	}

	freed, entries, err := cache.Clean(dir)
	if err != nil {
		fmt.Fprintf(stderr, "depscan: could not remove the cache: %v\n", err)
		return ExitOperational
	}
	if entries == 0 {
		fmt.Fprintf(stdout, "Nothing to remove: %s is already empty.\n", dir)
		return ExitOK
	}

	fmt.Fprintf(stdout, "Removed %d entries, freed %s\n  %s\n", entries, humanBytes(freed), dir)
	return ExitOK
}

// humanBytes renders a byte count in the largest unit that keeps it readable.
func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for size := n / unit; size >= unit && exp < 3; size /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGT"[exp])
}
