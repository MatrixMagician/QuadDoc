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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
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
		change, unfixed, err := fixFile(project, path, byUnit[path], networkUnit)
		if err != nil {
			return nil, err
		}
		result.Unfixed = append(result.Unfixed, unfixed...)
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
	// A file the project did not load, such as a sibling left out of the
	// paths given, is not ours to replace.
	if _, err := os.Lstat(path); err == nil {
		return Change{}, fmt.Errorf("%s already exists but is not among the units being fixed; "+
			"include it in the paths given to quaddoc, or move it aside, and re-run", path)
	}
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

// fixFile applies every fixable finding for one file. Findings whose fix
// declines are returned as unfixed, so the user still hears about them.
func fixFile(project *ir.Project, path string, findings []rules.Finding, networkUnit string) (Change, []rules.Finding, error) {
	original, err := os.ReadFile(path)
	if err != nil {
		return Change{}, nil, fmt.Errorf("reading %s: %w", path, err)
	}

	parsed, err := quadlet.Parse(path, strings.NewReader(string(original)))
	if err != nil {
		return Change{}, nil, err
	}

	// The fixes work in logical lines, so a continued entry is never split,
	// and each keeps the physical line Number it was parsed at, so an
	// insertion does not shift the line a later finding cites.
	lines := parsed.Lines
	applied := map[string]bool{}
	var unfixed []rules.Finding

	for _, f := range findings {
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
		} else {
			unfixed = append(unfixed, f)
		}
	}
	parsed.Lines = lines

	ruleIDs := make([]string, 0, len(applied))
	for id := range applied {
		ruleIDs = append(ruleIDs, id)
	}
	sort.Strings(ruleIDs)

	return Change{
		Path:   path,
		Before: string(original),
		After:  parsed.Render(),
		Rules:  ruleIDs,
	}, unfixed, nil
}

// entry builds a new single-line Key=value line for a fix to insert.
func entry(section, key, value string) quadlet.Line {
	return quadlet.Line{
		Kind: quadlet.LineEntry, Raw: []string{key + "=" + value},
		Section: section, Key: key, Value: value,
	}
}

// fixQD001 appends the SELinux relabelling option to a Volume= or Mount= line.
//
// The option to use was decided by the rule, which had the project-wide sharing
// map; the fix does not re-derive it. That is what keeps the fix from writing a
// :Z that QD002 would then flag.
func fixQD001(lines []quadlet.Line, f rules.Finding) ([]quadlet.Line, bool) {
	idx := slices.IndexFunc(lines, func(l quadlet.Line) bool {
		return l.Kind == quadlet.LineEntry && l.Number == f.Line
	})
	// A continued entry is left alone: the option belongs at the end of the
	// value, and rewriting a continuation is not worth the risk of splitting it.
	if idx < 0 || len(lines[idx].Raw) != 1 {
		return lines, false
	}
	l := lines[idx]

	option := f.Fix["option"]
	if option != "z" && option != "Z" {
		return lines, false
	}

	// Idempotence: a line that already carries a label is left alone.
	switch l.Key {
	case "Volume":
		if hasLabelOption(l.Value) {
			return lines, false
		}
		l.Value = appendOption(l.Value, option)
	case "Mount":
		// relabel=private and relabel=shared are what podman-run(1) --mount
		// documents; Podman 5.8.4 turns them into the :Z and :z a Volume=
		// would carry, and Quadlet passes the value through unchanged.
		m, ok := ir.ParseMountKey(l.Value, l.Number)
		if !ok || m.HasSELinuxLabel() {
			return lines, false
		}
		l.Value = strings.TrimSpace(l.Value) + "," + ir.MountKeySpelling[option]
	default:
		return lines, false
	}

	key, _, _ := strings.Cut(l.Raw[0], "=")
	l.Raw = []string{key + "=" + l.Value}
	lines[idx] = l
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
func fixQD022(lines []quadlet.Line) ([]quadlet.Line, bool) {
	// Idempotence: if the section already has a key, there is nothing to do.
	// A commented-out key is not a key.
	for _, l := range lines {
		if l.Kind == quadlet.LineEntry && l.Section == "Install" {
			return lines, false
		}
	}

	wantedBy := entry("Install", "WantedBy", "default.target")

	// Fill in an existing empty [Install], or add the whole section.
	for i, l := range lines {
		if l.Kind == quadlet.LineSection && l.Section == "Install" {
			return slices.Insert(lines, i+1, wantedBy), true
		}
	}

	if n := len(lines); n > 0 && lines[n-1].Kind != quadlet.LineBlank {
		lines = append(lines, quadlet.Line{Kind: quadlet.LineBlank, Raw: []string{""}})
	}
	header := quadlet.Line{Kind: quadlet.LineSection, Raw: []string{"[Install]"}, Section: "Install"}
	return append(lines, header, wantedBy), true
}

// fixQD030 adds a Network= key to a container unit.
func fixQD030(lines []quadlet.Line, networkUnit string) ([]quadlet.Line, bool) {
	if networkUnit == "" {
		return lines, false
	}
	want := networkUnit + ".network"

	// Insert after the last entry of the [Container] section, so the key lands
	// where a human would have put it and never inside a continued entry.
	insertAt := -1
	for i, l := range lines {
		if l.Section != "Container" {
			continue
		}
		// Idempotence: already wired in.
		if l.Kind == quadlet.LineEntry && l.Key == "Network" && l.Value == want {
			return lines, false
		}
		if l.Kind == quadlet.LineSection || l.Kind == quadlet.LineEntry {
			insertAt = i + 1
		}
	}
	if insertAt < 0 {
		return lines, false
	}
	return slices.Insert(lines, insertAt, entry("Container", "Network", want)), true
}

// Write applies the changes to disk.
func Write(result *Result) error {
	for _, change := range result.Changes {
		if !change.Modified() {
			continue
		}
		if err := writeFile(change); err != nil {
			return fmt.Errorf("writing %s: %w", change.Path, err)
		}
	}
	return nil
}

// writeFile writes one change. A created file is opened with O_EXCL, so a file
// that appeared since Apply checked the disk is never truncated.
func writeFile(change Change) error {
	if !change.Created {
		return os.WriteFile(change.Path, []byte(change.After), 0o644)
	}
	f, err := os.OpenFile(change.Path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	_, err = f.WriteString(change.After)
	return errors.Join(err, f.Close())
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
