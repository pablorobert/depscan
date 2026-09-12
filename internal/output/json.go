package output

import (
	"encoding/json"
	"io"

	"github.com/pablorobert/depscan/internal/model"
)

// WriteJSON emits the report as the only thing on the stream. Progress and diagnostics
// belong on stderr, so a consumer can pipe stdout straight into a parser.
func WriteJSON(w io.Writer, r *model.Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	// Advisory titles and URLs are plain text; escaping them would only make the
	// document harder to read.
	enc.SetEscapeHTML(false)
	return enc.Encode(r)
}
