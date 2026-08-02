// Package output renders findings for people and for machines.
package output

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/MatrixMagician/quaddoc/internal/rules"
)

// Human renders findings grouped by unit, with colour when the destination is a
// terminal that wants it.
type Human struct {
	// Colour enables ANSI styling. Callers should set it from a terminal
	// check and the NO_COLOR convention.
	Colour bool
	// Verbose includes each rule's rationale and citation, for a user meeting
	// a rule for the first time.
	Verbose bool
}

// ColourEnabled reports whether ANSI styling is appropriate for a stream,
// honouring the NO_COLOR convention (https://no-color.org).
func ColourEnabled(w io.Writer) bool {
	if _, set := os.LookupEnv("NO_COLOR"); set {
		return false
	}
	if os.Getenv("TERM") == "dumb" {
		return false
	}
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

const (
	ansiReset  = "\033[0m"
	ansiBold   = "\033[1m"
	ansiDim    = "\033[2m"
	ansiRed    = "\033[31m"
	ansiYellow = "\033[33m"
	ansiBlue   = "\033[34m"
	ansiCyan   = "\033[36m"
)

func (h Human) style(code, s string) string {
	if !h.Colour {
		return s
	}
	return code + s + ansiReset
}

func (h Human) severityLabel(s rules.Severity) string {
	switch s {
	case rules.Error:
		return h.style(ansiRed+ansiBold, "error")
	case rules.Warning:
		return h.style(ansiYellow+ansiBold, "warning")
	}
	return h.style(ansiBlue, "note")
}

// Render writes the findings. It returns nothing: rendering failures on a
// terminal are not worth propagating, and a failed write to a file surfaces
// when the caller closes it.
func (h Human) Render(w io.Writer, findings []rules.Finding) {
	if len(findings) == 0 {
		fmt.Fprintln(w, h.style(ansiBold, "No problems found."))
		return
	}

	byUnit := map[string][]rules.Finding{}
	var units []string
	for _, f := range findings {
		if _, seen := byUnit[f.Unit]; !seen {
			units = append(units, f.Unit)
		}
		byUnit[f.Unit] = append(byUnit[f.Unit], f)
	}
	sort.Strings(units)

	for i, unit := range units {
		if i > 0 {
			fmt.Fprintln(w)
		}
		fmt.Fprintln(w, h.style(ansiBold, unit))

		for _, f := range byUnit[unit] {
			location := ""
			if f.Line > 0 {
				location = h.style(ansiDim, fmt.Sprintf(":%d", f.Line))
			}
			confidence := ""
			if f.Confidence == rules.Possible {
				confidence = h.style(ansiDim, " (possible; run with --host-context to confirm)")
			}

			fmt.Fprintf(w, "  %s%s %s %s%s\n",
				h.severityLabel(f.Severity), location,
				h.style(ansiCyan, f.RuleID), f.Message, confidence)

			for _, line := range strings.Split(strings.TrimRight(f.Remediation, "\n"), "\n") {
				if line == "" {
					// Do not indent a blank line: it only adds trailing
					// whitespace, which shows up in diffs and golden files.
					fmt.Fprintln(w)
					continue
				}
				fmt.Fprintf(w, "    %s\n", h.style(ansiDim, line))
			}

			if h.Verbose {
				if r, ok := rules.Lookup(f.RuleID); ok {
					fmt.Fprintf(w, "    %s\n", h.style(ansiDim, "why: "+r.Rationale))
					fmt.Fprintf(w, "    %s\n", h.style(ansiDim, "source: "+r.Citation))
				}
			}
		}
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, h.summary(findings))
}

func (h Human) summary(findings []rules.Finding) string {
	var errs, warns, notes int
	for _, f := range findings {
		switch f.Severity {
		case rules.Error:
			errs++
		case rules.Warning:
			warns++
		default:
			notes++
		}
	}

	var parts []string
	if errs > 0 {
		parts = append(parts, h.style(ansiRed, plural(errs, "error", "errors")))
	}
	if warns > 0 {
		parts = append(parts, h.style(ansiYellow, plural(warns, "warning", "warnings")))
	}
	if notes > 0 {
		parts = append(parts, h.style(ansiBlue, plural(notes, "note", "notes")))
	}
	return h.style(ansiBold, "Found ") + strings.Join(parts, ", ") + "."
}

func plural(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %s", n, many)
}
