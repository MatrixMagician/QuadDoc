package output

import (
	"encoding/json"
	"io"

	"github.com/MatrixMagician/quaddoc/internal/rules"
)

// Report is the stable JSON schema. It is a published contract: fields may be
// added, but existing ones do not change meaning or type.
type Report struct {
	// Version is the schema version, so consumers can detect a breaking
	// change rather than guessing.
	Version int `json:"version"`
	// Findings are ordered deterministically: by unit, then line, then rule.
	Findings []rules.Finding `json:"findings"`
	// Summary counts findings by severity, so a consumer need not aggregate.
	Summary Summary `json:"summary"`
}

// Summary counts findings by severity.
type Summary struct {
	Errors   int `json:"errors"`
	Warnings int `json:"warnings"`
	Notes    int `json:"notes"`
}

// SchemaVersion is the current JSON schema version.
const SchemaVersion = 1

// JSON writes the report. Findings is never null in the output: an empty run
// produces `[]`, so consumers can iterate without a nil check.
func JSON(w io.Writer, findings []rules.Finding) error {
	if findings == nil {
		findings = []rules.Finding{}
	}

	report := Report{Version: SchemaVersion, Findings: findings}
	for _, f := range findings {
		switch f.Severity {
		case rules.Error:
			report.Summary.Errors++
		case rules.Warning:
			report.Summary.Warnings++
		default:
			report.Summary.Notes++
		}
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}
