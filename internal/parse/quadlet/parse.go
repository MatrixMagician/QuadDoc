// Package quadlet parses systemd unit files with Quadlet semantics.
//
// The format is systemd's INI dialect, which differs from common INI in ways
// that matter here:
//
//   - Keys may repeat within a section. `Volume=` appearing five times is five
//     mounts, not one key overwritten four times, so the model is a list of
//     entries rather than a map.
//   - A line ending in a backslash continues onto the next line. systemd joins
//     the fragments with a space, so the joined value is not simply the
//     concatenation of the parts.
//   - Both `#` and `;` start a comment, but only at the beginning of a line.
//     A `#` inside a value is part of the value.
//   - The same section may appear more than once; systemd treats the second
//     occurrence as a continuation of the first.
//
// Parsing preserves enough of the original text to render it back byte for
// byte. The fix engine depends on that: rewriting one mount option must not
// reflow comments or reorder keys elsewhere in the file.
//
// Reference: systemd.syntax(7) and podman-systemd.unit(5).
package quadlet

import (
	"fmt"
	"io"
	"strings"
)

// LineKind classifies a physical line, so rendering can reproduce the original
// file without keeping a second copy of it.
type LineKind int

const (
	// LineBlank is an empty or whitespace-only line.
	LineBlank LineKind = iota
	// LineComment is a line whose first non-space character is '#' or ';'.
	LineComment
	// LineSection is a `[Section]` header.
	LineSection
	// LineEntry is a `Key=value` assignment, possibly spanning continuations.
	LineEntry
	// LineUnknown is a line we could not classify. It is preserved verbatim
	// and reported, rather than being silently dropped.
	LineUnknown
)

// Line is one logical line of a unit file. A logical line spans several
// physical lines when continuations are used.
type Line struct {
	Kind LineKind
	// Raw holds the original physical lines, without their terminators, so
	// the file can be rendered back exactly as it arrived.
	Raw []string
	// Number is the 1-based physical line number where this logical line
	// starts. Findings cite it.
	Number int

	// Section is set for LineSection: the name inside the brackets.
	Section string

	// Key and Value are set for LineEntry. Value is the logical value, with
	// continuations already joined; Raw retains how it was written.
	Key   string
	Value string
}

// Entry is a single Key=value assignment together with the section it appeared
// in. Rules work in terms of entries.
type Entry struct {
	Section string
	Key     string
	Value   string
	Line    int
}

// File is a parsed unit file that can be rendered back to its original bytes.
type File struct {
	// Path is where the file came from. Findings cite it.
	Path string
	// Lines is every logical line in order, including blanks and comments.
	Lines []Line
	// trailingNewline records whether the source ended with a newline, so
	// rendering does not add or drop one.
	trailingNewline bool
}

// Parse reads a unit file. It does not fail on unrecognised lines: a linter
// that refuses to parse is useless on exactly the malformed files a user most
// needs linted. Such lines are kept as LineUnknown for a rule to report.
func Parse(path string, r io.Reader) (*File, error) {
	f := &File{Path: path}

	raw, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	// Split by hand rather than with bufio.Scanner: the scanner discards the
	// difference between a file ending in a newline and one that does not,
	// and Render must reproduce the input exactly.
	text := string(raw)
	f.trailingNewline = strings.HasSuffix(text, "\n")
	text = strings.TrimSuffix(text, "\n")

	var physical []string
	if text != "" || f.trailingNewline {
		physical = strings.Split(text, "\n")
	}

	section := ""
	for i := 0; i < len(physical); {
		raw := physical[i]
		start := i + 1
		trimmed := strings.TrimSpace(raw)

		switch {
		case trimmed == "":
			f.Lines = append(f.Lines, Line{Kind: LineBlank, Raw: []string{raw}, Number: start})
			i++

		case strings.HasPrefix(trimmed, "#"), strings.HasPrefix(trimmed, ";"):
			f.Lines = append(f.Lines, Line{Kind: LineComment, Raw: []string{raw}, Number: start})
			i++

		case strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]"):
			section = strings.TrimSpace(trimmed[1 : len(trimmed)-1])
			f.Lines = append(f.Lines, Line{
				Kind: LineSection, Raw: []string{raw}, Number: start, Section: section,
			})
			i++

		default:
			// An entry, possibly continued. Gather physical lines while each
			// ends in an unescaped backslash.
			group := []string{raw}
			for continues(raw) && i+1 < len(physical) {
				i++
				raw = physical[i]
				group = append(group, raw)
			}
			i++

			key, value, ok := splitEntry(group)
			if !ok {
				f.Lines = append(f.Lines, Line{Kind: LineUnknown, Raw: group, Number: start})
				continue
			}
			f.Lines = append(f.Lines, Line{
				Kind: LineEntry, Raw: group, Number: start,
				Section: section, Key: key, Value: value,
			})
		}
	}
	return f, nil
}

// continues reports whether a physical line is continued on the next one.
// A backslash that is itself escaped does not continue the line.
func continues(s string) bool {
	trailing := 0
	for i := len(s) - 1; i >= 0 && s[i] == '\\'; i-- {
		trailing++
	}
	return trailing%2 == 1
}

// splitEntry turns a group of physical lines into a key and a logical value.
// systemd joins continuation fragments with a space.
func splitEntry(group []string) (key, value string, ok bool) {
	first := group[0]
	eq := strings.Index(first, "=")
	if eq < 0 {
		return "", "", false
	}
	key = strings.TrimSpace(first[:eq])
	if key == "" {
		return "", "", false
	}

	parts := make([]string, 0, len(group))
	parts = append(parts, strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(first[eq+1:]), "\\")))
	for _, more := range group[1:] {
		parts = append(parts, strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(more), "\\")))
	}

	// Drop empty fragments so a continuation with a blank tail does not
	// introduce a double space.
	kept := parts[:0]
	for _, p := range parts {
		if p != "" {
			kept = append(kept, p)
		}
	}
	return key, strings.Join(kept, " "), true
}

// Render writes the file back out. For an unmodified file the result is
// byte-identical to the input; this is asserted by a round-trip test over every
// fixture.
func (f *File) Render() string {
	var b strings.Builder
	for _, l := range f.Lines {
		for _, raw := range l.Raw {
			b.WriteString(raw)
			b.WriteByte('\n')
		}
	}
	out := b.String()
	if !f.trailingNewline {
		out = strings.TrimSuffix(out, "\n")
	}
	return out
}

// Entries returns every assignment in file order.
func (f *File) Entries() []Entry {
	var out []Entry
	for _, l := range f.Lines {
		if l.Kind == LineEntry {
			out = append(out, Entry{Section: l.Section, Key: l.Key, Value: l.Value, Line: l.Number})
		}
	}
	return out
}

// Section returns every entry in the named section, in file order. Section
// names are matched case-insensitively, as systemd does.
func (f *File) Section(name string) []Entry {
	var out []Entry
	for _, e := range f.Entries() {
		if strings.EqualFold(e.Section, name) {
			out = append(out, e)
		}
	}
	return out
}

// Values returns the values of every occurrence of a key within a section, in
// file order. Repeated keys are the norm in Quadlet, so this, not a lookup of
// one value, is the primary accessor.
func (f *File) Values(section, key string) []string {
	var out []string
	for _, e := range f.Section(section) {
		if strings.EqualFold(e.Key, key) {
			out = append(out, e.Value)
		}
	}
	return out
}

// Lookup returns the last value of a key within a section. systemd's
// last-one-wins applies to keys that are not list-valued; for list-valued keys
// use Values.
func (f *File) Lookup(section, key string) (string, bool) {
	vs := f.Values(section, key)
	if len(vs) == 0 {
		return "", false
	}
	return vs[len(vs)-1], true
}

// HasSection reports whether the named section appears at all, even empty. The
// distinction matters for `[Install]`: an empty one is still a statement of
// intent, whereas an absent one means the unit will never autostart.
func (f *File) HasSection(name string) bool {
	for _, l := range f.Lines {
		if l.Kind == LineSection && strings.EqualFold(l.Section, name) {
			return true
		}
	}
	return false
}
