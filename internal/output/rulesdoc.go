package output

import (
	"fmt"
	"strings"

	"github.com/MatrixMagician/quaddoc/internal/rules"
)

// RulesMarkdown renders the rule reference.
//
// It is generated from the same metadata the engine uses, so the published
// documentation cannot drift from what the code does. That is the payoff for
// keeping the citation and rationale in the rule struct rather than in a
// separate document someone has to remember to update.
func RulesMarkdown() string {
	var b strings.Builder

	b.WriteString("# QuadDoc rule reference\n\n")
	b.WriteString("Generated from the rule metadata by `quaddoc rules --markdown`.\n")
	b.WriteString("Every rule cites the documentation or observed behaviour it encodes.\n\n")

	b.WriteString("| Rule | Severity | Fixable | Summary |\n")
	b.WriteString("| --- | --- | --- | --- |\n")
	for _, r := range rules.All() {
		fixable := ""
		if r.Fixable {
			fixable = "yes"
		}
		fmt.Fprintf(&b, "| [%s](#%s) | %s | %s | %s |\n",
			r.ID, strings.ToLower(r.ID), r.DefaultSeverity, fixable, r.Summary)
	}
	b.WriteString("\n")

	for _, r := range rules.All() {
		fmt.Fprintf(&b, "## %s\n\n", r.ID)
		fmt.Fprintf(&b, "**%s**\n\n", r.Summary)

		fmt.Fprintf(&b, "- Default severity: `%s`\n", r.DefaultSeverity)
		if r.Fixable {
			b.WriteString("- Fixable by `quaddoc fix`\n")
		}
		if r.NeedsHostContext {
			b.WriteString("- Confirmed with `--host-context`; reported as a possibility without it\n")
		}
		b.WriteString("\n")

		fmt.Fprintf(&b, "%s\n\n", r.Rationale)
		fmt.Fprintf(&b, "*Source: %s*\n\n", r.Citation)
	}

	return b.String()
}
