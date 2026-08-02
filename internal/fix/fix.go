// Package fix applies mechanically safe remediations.
//
// Only rules whose remediation is provably semantics-preserving get a fix.
// Everything else is explain-only, because a linter that silently changes
// meaning is worse than one that merely complains. QD002, for instance, has no
// fix: choosing between relaxing the label and separating the directories is a
// decision about what the user meant, not a mechanical transformation.
//
// Two properties are load-bearing and are asserted by test:
//
//   - Idempotence: applying a fix twice equals applying it once. Otherwise
//     running the tool in CI would produce an endless diff.
//   - Locality: bytes outside the region a fix touches are unchanged. This is
//     why the parser retains the original text of every line.
package fix

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/MatrixMagician/quaddoc/internal/ir"
	"github.com/MatrixMagician/quaddoc/internal/parse/quadlet"
	"github.com/MatrixMagician/quaddoc/internal/rules"
)

// Change is one file's worth of proposed edit.
type Change struct {
	// Path is the file to change. For a file that does not exist yet, such as
	// the network unit QD030 creates, Created is true.
	Path    string
	Before  string
	After   string
	Created bool
	// Rules lists the rule IDs that contributed to this change.
	Rules []string
}

// Modified reports whether the change actually alters anything.
func (c Change) Modified() bool { return c.Before != c.After }

// Result is everything a fix run proposes.
type Result struct {
	Changes []Change
	// Unfixed are findings whose rules have no mechanical fix, so the user
	// knows what is left to do by hand.
	Unfixed []rules.Finding
}

// Options control which fixes are applied.
type Options struct {
	// Only restricts fixing to these rule IDs. Empty means every fixable rule.
	Only map[string]bool
}

// Apply computes the changes that would resolve the given findings.
//
// It returns the proposed content rather than writing it, so the caller can
// show a diff first. Writing is a separate, explicit step.
func Apply(project *ir.Project, findings []rules.Finding, opts Options) (*Result, error) {
	result := &Result{}

	// Group findings by the file they concern, so each file is rewritten once
	// however many findings it carries.
	byUnit := map[string][]rules.Finding{}
	for _, f := range findings {
		rule, ok := rules.Lookup(f.RuleID)
		if !ok || !rule.Fixable {
			result.Unfixed = append(result.Unfixed, f)
			continue
		}
		if len(opts.Only) > 0 && !opts.Only[f.RuleID] {
			result.Unfixed = append(result.Unfixed, f)
			continue
		}
		byUnit[f.Unit] = append(byUnit[f.Unit], f)
	}

	// QD030 needs a network unit that may not exist yet, and every container
	// it affects must reference the same one, so it is resolved once for the
	// whole project rather than per file.
	networkUnit, needNetwork := plannedNetwork(project, findings, opts)
	if needNetwork {
		change, err := networkUnitChange(project, networkUnit)
		if err != nil {
			return nil, err
		}
		if change.Modified() {
			result.Changes = append(result.Changes, change)
		}
	}

	paths := make([]string, 0, len(byUnit))
	for path := range byUnit {
		paths = append(paths, path)
	}
	sort.Strings(paths)

	for _, path := range paths {
		change, err := fixFile(project, path, byUnit[path], networkUnit)
		if err != nil {
			return nil, err
		}
		if change.Modified() {
			result.Changes = append(result.Changes, change)
		}
	}

	sort.Slice(result.Changes, func(i, j int) bool {
		return result.Changes[i].Path < result.Changes[j].Path
	})
	return result, nil
}

// plannedNetwork decides which network unit QD030's fix should wire containers
// into, reusing one the project already has rather than adding a second.
func plannedNetwork(project *ir.Project, findings []rules.Finding, opts Options) (string, bool) {
	var wanted bool
	for _, f := range findings {
		if f.RuleID != "QD030" {
			continue
		}
		if len(opts.Only) > 0 && !opts.Only["QD030"] {
			continue
		}
		wanted = true
	}
	if !wanted {
		return "", false
	}

	for _, u := range project.Units {
		if u.Kind == ir.KindNetwork {
			return u.Name, true
		}
	}
	return "shared", true
}

// networkUnitChange produces the .network unit QD030's fix needs, creating it
// if the project has none.
func networkUnitChange(project *ir.Project, name string) (Change, error) {
	if u, ok := project.UnitByName(name, ir.KindNetwork); ok {
		// It already exists, so there is nothing to write.
		return Change{Path: u.Path, Before: "", After: ""}, nil
	}

	path := filepath.Join(project.Root, name+".network")
	content := fmt.Sprintf(`# Created by quaddoc to fix QD030.
#
# Podman's default network has DNS disabled, so containers on it cannot resolve
# each other by name. This user-defined network restores the behaviour a
# compose file would have given you.

[Network]
NetworkName=%s

[Install]
WantedBy=default.target
`, name)

	return Change{Path: path, After: content, Created: true, Rules: []string{"QD030"}}, nil
}

// fixFile applies every fixable finding for one file.
func fixFile(project *ir.Project, path string, findings []rules.Finding, networkUnit string) (Change, error) {
	original, err := os.ReadFile(path)
	if err != nil {
		return Change{}, fmt.Errorf("reading %s: %w", path, err)
	}

	parsed, err := quadlet.Parse(path, strings.NewReader(string(original)))
	if err != nil {
		return Change{}, err
	}

	// Sort findings by line, descending, so that edits do not disturb the
	// line numbers of edits not yet applied.
	sorted := append([]rules.Finding(nil), findings...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Line > sorted[j].Line })

	lines := renderLines(parsed)
	applied := map[string]bool{}

	for _, f := range sorted {
		var changed bool
		switch f.RuleID {
		case "QD001":
			lines, changed = fixQD001(lines, f)
		case "QD022":
			lines, changed = fixQD022(lines)
		case "QD030":
			lines, changed = fixQD030(lines, networkUnit)
		}
		if changed {
			applied[f.RuleID] = true
		}
	}

	ruleIDs := make([]string, 0, len(applied))
	for id := range applied {
		ruleIDs = append(ruleIDs, id)
	}
	sort.Strings(ruleIDs)

	return Change{
		Path:   path,
		Before: string(original),
		After:  strings.Join(lines, "\n") + trailing(string(original)),
		Rules:  ruleIDs,
	}, nil
}

// renderLines flattens a parsed file back to physical lines, which is the unit
// the fixes work in.
func renderLines(f *quadlet.File) []string {
	var lines []string
	for _, l := range f.Lines {
		lines = append(lines, l.Raw...)
	}
	return lines
}

// trailing preserves whether the original file ended with a newline.
func trailing(original string) string {
	if strings.HasSuffix(original, "\n") {
		return "\n"
	}
	return ""
}

// fixQD001 appends the SELinux relabelling option to a Volume= line.
//
// The option to use was decided by the rule, which had the project-wide sharing
// map; the fix does not re-derive it. That is what keeps the fix from writing a
// :Z that QD002 would then flag.
func fixQD001(lines []string, f rules.Finding) ([]string, bool) {
	idx := f.Line - 1
	if idx < 0 || idx >= len(lines) {
		return lines, false
	}

	line := lines[idx]
	key, value, ok := strings.Cut(line, "=")
	if !ok || !strings.EqualFold(strings.TrimSpace(key), "Volume") {
		return lines, false
	}

	// Idempotence: a line that already carries a label is left alone.
	if hasLabelOption(value) {
		return lines, false
	}

	option := f.Fix["option"]
	if option != "z" && option != "Z" {
		return lines, false
	}

	lines[idx] = key + "=" + appendOption(value, option)
	return lines, true
}

// hasLabelOption reports whether a Volume= value already carries :z or :Z.
func hasLabelOption(value string) bool {
	parts := strings.Split(strings.TrimSpace(value), ":")
	if len(parts) < 3 {
		return false
	}
	for _, o := range strings.Split(parts[len(parts)-1], ",") {
		if o == "z" || o == "Z" {
			return true
		}
	}
	return false
}

// appendOption adds an option to a Volume= value, in the options field.
func appendOption(value, option string) string {
	trimmed := strings.TrimSpace(value)
	parts := strings.Split(trimmed, ":")

	// source:dest has no options field yet; source:dest:opts does.
	if len(parts) >= 3 {
		return trimmed + "," + option
	}
	return trimmed + ":" + option
}

// fixQD022 appends an [Install] section.
func fixQD022(lines []string) ([]string, bool) {
	// Idempotence: if the section already has a key, there is nothing to do.
	inInstall := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[") {
			inInstall = strings.EqualFold(trimmed, "[Install]")
			continue
		}
		if inInstall && strings.Contains(trimmed, "=") {
			return lines, false
		}
	}

	// Append to an existing empty [Install], or add the whole section.
	for i, line := range lines {
		if strings.EqualFold(strings.TrimSpace(line), "[Install]") {
			rest := append([]string{"WantedBy=default.target"}, lines[i+1:]...)
			return append(lines[:i+1], rest...), true
		}
	}

	out := append([]string{}, lines...)
	if len(out) > 0 && strings.TrimSpace(out[len(out)-1]) != "" {
		out = append(out, "")
	}
	return append(out, "[Install]", "WantedBy=default.target"), true
}

// fixQD030 adds a Network= key to a container unit.
func fixQD030(lines []string, networkUnit string) ([]string, bool) {
	if networkUnit == "" {
		return lines, false
	}
	want := "Network=" + networkUnit + ".network"

	// Idempotence: already wired in.
	for _, line := range lines {
		if strings.TrimSpace(line) == want {
			return lines, false
		}
	}

	// Insert at the end of the [Container] section, so the key lands where a
	// human would have put it.
	insertAt := -1
	inContainer := false
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[") {
			if inContainer {
				break
			}
			inContainer = strings.EqualFold(trimmed, "[Container]")
			continue
		}
		if inContainer && strings.Contains(trimmed, "=") {
			insertAt = i + 1
		}
	}
	if insertAt < 0 {
		return lines, false
	}

	out := append([]string{}, lines[:insertAt]...)
	out = append(out, want)
	return append(out, lines[insertAt:]...), true
}

// Write applies the changes to disk.
func Write(result *Result) error {
	for _, change := range result.Changes {
		if !change.Modified() {
			continue
		}
		if err := os.WriteFile(change.Path, []byte(change.After), 0o644); err != nil {
			return fmt.Errorf("writing %s: %w", change.Path, err)
		}
	}
	return nil
}

// Diff renders a unified diff of a change, for previewing.
func Diff(c Change) string {
	if !c.Modified() {
		return ""
	}

	var b strings.Builder
	if c.Created {
		fmt.Fprintf(&b, "--- /dev/null\n+++ %s\n", c.Path)
	} else {
		fmt.Fprintf(&b, "--- %s\n+++ %s\n", c.Path, c.Path)
	}

	before := strings.Split(strings.TrimSuffix(c.Before, "\n"), "\n")
	after := strings.Split(strings.TrimSuffix(c.After, "\n"), "\n")
	if c.Before == "" {
		before = nil
	}

	for _, line := range diffLines(before, after) {
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
}

// diffLines produces a simple line diff. It is not a minimal edit script, but
// unit files are short and the changes are small, so a straightforward
// longest-common-subsequence walk reads clearly.
func diffLines(before, after []string) []string {
	lcs := longestCommonSubsequence(before, after)

	var out []string
	i, j := 0, 0
	for _, common := range lcs {
		for i < len(before) && before[i] != common {
			out = append(out, "-"+before[i])
			i++
		}
		for j < len(after) && after[j] != common {
			out = append(out, "+"+after[j])
			j++
		}
		out = append(out, " "+common)
		i++
		j++
	}
	for ; i < len(before); i++ {
		out = append(out, "-"+before[i])
	}
	for ; j < len(after); j++ {
		out = append(out, "+"+after[j])
	}
	return out
}

func longestCommonSubsequence(a, b []string) []string {
	table := make([][]int, len(a)+1)
	for i := range table {
		table[i] = make([]int, len(b)+1)
	}
	for i := len(a) - 1; i >= 0; i-- {
		for j := len(b) - 1; j >= 0; j-- {
			if a[i] == b[j] {
				table[i][j] = table[i+1][j+1] + 1
				continue
			}
			table[i][j] = max(table[i+1][j], table[i][j+1])
		}
	}

	var out []string
	for i, j := 0, 0; i < len(a) && j < len(b); {
		switch {
		case a[i] == b[j]:
			out = append(out, a[i])
			i++
			j++
		case table[i+1][j] >= table[i][j+1]:
			i++
		default:
			j++
		}
	}
	return out
}
