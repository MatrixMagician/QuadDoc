// Package config reads per-project rule settings.
//
// The format is deliberately small: which rules to run, and at what severity.
// Anything more expressive invites configuration that encodes a policy nobody
// remembers agreeing to.
//
// Inline `# quaddoc: disable=QD001 reason` comments suppress a rule for one
// unit. The reason is mandatory, and a disable without one is itself reported,
// because a suppression whose justification has been lost is indistinguishable
// from a bug someone gave up on.
package config

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/MatrixMagician/quaddoc/internal/rules"
)

// FileName is the per-project configuration file.
const FileName = ".quaddoc.toml"

// Config is a project's rule settings.
type Config struct {
	// Disabled lists rule IDs to skip entirely.
	Disabled map[string]bool
	// Severity maps a rule ID to the severity to report it at.
	Severity map[string]rules.Severity
	// Path is where the configuration was read from, empty if none was found.
	Path string
}

// Load reads configuration for a project, searching the directory and its
// parents so that a repository-wide file applies to units in subdirectories.
func Load(start string) (*Config, error) {
	cfg := &Config{
		Disabled: map[string]bool{},
		Severity: map[string]rules.Severity{},
	}

	path, found := findUpwards(start, FileName)
	if !found {
		return cfg, nil
	}
	cfg.Path = path

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	if err := parse(string(data), cfg); err != nil {
		return nil, fmt.Errorf("in %s: %w", path, err)
	}
	return cfg, nil
}

// findUpwards looks for a file in a directory and each of its parents.
func findUpwards(start, name string) (string, bool) {
	dir, err := filepath.Abs(start)
	if err != nil {
		return "", false
	}
	if info, err := os.Stat(dir); err == nil && !info.IsDir() {
		dir = filepath.Dir(dir)
	}

	for {
		candidate := filepath.Join(dir, name)
		if _, err := os.Stat(candidate); err == nil {
			return candidate, true
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", false
		}
		dir = parent
	}
}

// parse reads the configuration format, which is the subset of TOML this needs:
// a [rules] table mapping rule IDs to a severity or to "off".
//
//	[rules]
//	QD001 = "warning"   # report it, but do not fail the build
//	QD041 = "off"       # we keep secrets in the unit deliberately
//
// Written by hand rather than pulled in as a dependency: the grammar is four
// lines of parsing, and a TOML library would be the project's only runtime
// dependency outside the compose loader.
func parse(text string, cfg *Config) error {
	section := ""

	sc := bufio.NewScanner(strings.NewReader(text))
	for line := 1; sc.Scan(); line++ {
		raw := strings.TrimSpace(sc.Text())
		if raw == "" || strings.HasPrefix(raw, "#") {
			continue
		}

		if strings.HasPrefix(raw, "[") && strings.HasSuffix(raw, "]") {
			section = strings.ToLower(strings.TrimSpace(raw[1 : len(raw)-1]))
			continue
		}

		key, value, ok := strings.Cut(raw, "=")
		if !ok {
			return fmt.Errorf("line %d: expected key = value, got %q", line, raw)
		}
		key = strings.ToUpper(strings.TrimSpace(key))
		value = strings.Trim(strings.TrimSpace(stripComment(value)), `"'`)

		if section != "rules" {
			return fmt.Errorf("line %d: %q is outside a [rules] table", line, key)
		}
		if _, known := rules.Lookup(key); !known {
			return fmt.Errorf("line %d: no such rule %q", line, key)
		}

		if strings.EqualFold(value, "off") || strings.EqualFold(value, "false") {
			cfg.Disabled[key] = true
			continue
		}
		severity, ok := rules.ParseSeverity(value)
		if !ok {
			return fmt.Errorf("line %d: %q is not a severity; use error, warning, note, or off",
				line, value)
		}
		cfg.Severity[key] = severity
	}
	return sc.Err()
}

// stripComment removes a trailing comment from a value, leaving quoted hashes
// alone.
func stripComment(value string) string {
	var quote rune
	for i, r := range value {
		switch {
		case quote != 0 && r == quote:
			quote = 0
		case quote == 0 && (r == '"' || r == '\''):
			quote = r
		case quote == 0 && r == '#':
			return value[:i]
		}
	}
	return value
}

// RuleConfig converts to the engine's configuration.
func (c *Config) RuleConfig() rules.Config {
	return rules.Config{Disabled: c.Disabled, SeverityOverride: c.Severity}
}

// Suppression is an inline `# quaddoc: disable=...` directive.
type Suppression struct {
	// Rules are the rule IDs suppressed, empty for all of them.
	Rules []string
	// Reason is why. Mandatory.
	Reason string
	// Line is where the directive appeared.
	Line int
	// Unit is the file it appeared in.
	Unit string
}

// Covers reports whether a suppression applies to a finding.
func (s Suppression) Covers(ruleID string) bool {
	if len(s.Rules) == 0 {
		return true
	}
	for _, id := range s.Rules {
		if strings.EqualFold(id, ruleID) {
			return true
		}
	}
	return false
}

const directivePrefix = "quaddoc:"

// ParseSuppressions finds inline directives in a unit file's text.
//
// A directive applies to the whole file rather than to the following line.
// Line-scoped suppression sounds tidier but breaks the moment someone reformats
// the file, and a suppression that silently stops applying is worse than one
// with a slightly broad scope.
func ParseSuppressions(unit, text string) []Suppression {
	var out []Suppression

	sc := bufio.NewScanner(strings.NewReader(text))
	for line := 1; sc.Scan(); line++ {
		trimmed := strings.TrimSpace(sc.Text())
		if !strings.HasPrefix(trimmed, "#") && !strings.HasPrefix(trimmed, ";") {
			continue
		}

		body := strings.TrimSpace(strings.TrimLeft(trimmed, "#; "))
		if !strings.HasPrefix(body, directivePrefix) {
			continue
		}
		body = strings.TrimSpace(strings.TrimPrefix(body, directivePrefix))

		if !strings.HasPrefix(body, "disable") {
			continue
		}
		body = strings.TrimSpace(strings.TrimPrefix(body, "disable"))

		s := Suppression{Line: line, Unit: unit}
		if strings.HasPrefix(body, "=") {
			ids, reason, _ := strings.Cut(strings.TrimPrefix(body, "="), " ")
			for _, id := range strings.Split(ids, ",") {
				if id = strings.ToUpper(strings.TrimSpace(id)); id != "" {
					s.Rules = append(s.Rules, id)
				}
			}
			s.Reason = strings.TrimSpace(reason)
		} else {
			s.Reason = strings.TrimSpace(body)
		}

		out = append(out, s)
	}
	return out
}

// ApplySuppressions removes findings covered by a directive, and reports
// directives that gave no reason.
//
// The reason is mandatory because the cost of a suppression is paid later, by
// whoever finds it and cannot tell whether it is still justified.
//
// The config argument supplies severity overrides for QD000, which is raised
// here rather than by the rule engine and so would otherwise ignore them.
func (c *Config) ApplySuppressions(findings []rules.Finding, byUnit map[string][]Suppression) []rules.Finding {
	var kept []rules.Finding

	for _, f := range findings {
		suppressed := false
		for _, s := range byUnit[f.Unit] {
			if s.Reason != "" && s.Covers(f.RuleID) {
				suppressed = true
				break
			}
		}
		if !suppressed {
			kept = append(kept, f)
		}
	}

	// A directive with no reason suppresses nothing and is reported. QD000 is
	// raised here rather than by the engine, so both halves of its
	// configuration have to be applied by hand; the engine's central handling
	// does not reach it.
	if c != nil && c.Disabled["QD000"] {
		return kept
	}

	severity := rules.Warning
	if c != nil {
		if override, ok := c.Severity["QD000"]; ok {
			severity = override
		}
	}

	// Sort the units so the reported order does not depend on map iteration.
	units := make([]string, 0, len(byUnit))
	for unit := range byUnit {
		units = append(units, unit)
	}
	sort.Strings(units)

	for _, unit := range units {
		for _, s := range byUnit[unit] {
			if s.Reason != "" {
				continue
			}
			kept = append(kept, rules.Finding{
				RuleID:     "QD000",
				Severity:   severity,
				SeverityJS: severity.String(),
				Confidence: rules.Confirmed,
				Unit:       unit,
				Line:       s.Line,
				Message:    "a quaddoc disable directive gives no reason, so it is ignored",
				Remediation: "Say why the rule does not apply here, on the same line:\n\n" +
					"    # quaddoc: disable=QD001 this path is on a filesystem we label at mount time\n\n" +
					"The reason is what lets the next person judge whether it still holds.",
			})
		}
	}
	return kept
}
