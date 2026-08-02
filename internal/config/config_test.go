package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MatrixMagician/quaddoc/internal/rules"
)

func TestParseSeverityOverrides(t *testing.T) {
	cfg := &Config{Disabled: map[string]bool{}, Severity: map[string]rules.Severity{}}

	err := parse(`
# A project may decide a rule matters less to it.
[rules]
QD001 = "warning"
QD040 = "off"
QD041 = "note"   # trailing comments are allowed
`, cfg)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if got := cfg.Severity["QD001"]; got != rules.Warning {
		t.Errorf("QD001 severity = %v, want Warning", got)
	}
	if !cfg.Disabled["QD040"] {
		t.Error("QD040 should be disabled")
	}
	if got := cfg.Severity["QD041"]; got != rules.Note {
		t.Errorf("QD041 severity = %v, want Note", got)
	}
}

func TestParseRejectsUnknownRules(t *testing.T) {
	// A typo'd rule ID would otherwise sit in the file doing nothing, which
	// the author would not discover until the rule they meant to configure
	// fired in CI.
	cfg := &Config{Disabled: map[string]bool{}, Severity: map[string]rules.Severity{}}

	err := parse("[rules]\nQD999 = \"off\"\n", cfg)
	if err == nil {
		t.Fatal("an unknown rule ID should be rejected")
	}
}

func TestParseRejectsUnknownSeverity(t *testing.T) {
	cfg := &Config{Disabled: map[string]bool{}, Severity: map[string]rules.Severity{}}

	err := parse("[rules]\nQD001 = \"critical\"\n", cfg)
	if err == nil {
		t.Fatal("an unknown severity should be rejected")
	}
}

func TestParseRejectsKeysOutsideRulesTable(t *testing.T) {
	cfg := &Config{Disabled: map[string]bool{}, Severity: map[string]rules.Severity{}}

	if err := parse("QD001 = \"off\"\n", cfg); err == nil {
		t.Fatal("a key outside [rules] should be rejected")
	}
}

func TestLoadSearchesParentDirectories(t *testing.T) {
	// A repository-wide file should govern units in subdirectories.
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, FileName),
		[]byte("[rules]\nQD001 = \"note\"\n"), 0o644); err != nil {
		t.Fatalf("writing config: %v", err)
	}

	nested := filepath.Join(root, "deploy", "units")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatalf("creating directories: %v", err)
	}

	cfg, err := Load(nested)
	if err != nil {
		t.Fatalf("loading: %v", err)
	}
	if cfg.Path == "" {
		t.Fatal("the parent configuration was not found")
	}
	if got := cfg.Severity["QD001"]; got != rules.Note {
		t.Errorf("QD001 = %v, want Note", got)
	}
}

func TestLoadWithNoConfigIsNotAnError(t *testing.T) {
	// Most projects will not have one, and requiring it would be tiresome.
	cfg, err := Load(t.TempDir())
	if err != nil {
		t.Fatalf("loading: %v", err)
	}
	if cfg.Path != "" {
		t.Errorf("found a configuration where there is none: %s", cfg.Path)
	}
	if len(cfg.Disabled) != 0 || len(cfg.Severity) != 0 {
		t.Error("an absent configuration should disable and override nothing")
	}
}

func TestParseSuppressions(t *testing.T) {
	tests := []struct {
		name       string
		text       string
		wantRules  []string
		wantReason string
		wantCount  int
	}{
		{
			name:      "a rule and a reason",
			text:      "# quaddoc: disable=QD001 labelled at mount time\n[Container]\n",
			wantRules: []string{"QD001"}, wantReason: "labelled at mount time", wantCount: 1,
		},
		{
			name:      "several rules",
			text:      "# quaddoc: disable=QD001,QD002 deliberate\n[Container]\n",
			wantRules: []string{"QD001", "QD002"}, wantReason: "deliberate", wantCount: 1,
		},
		{
			name:      "a semicolon comment works too",
			text:      "; quaddoc: disable=QD001 a reason\n[Container]\n",
			wantRules: []string{"QD001"}, wantCount: 1,
		},
		{
			name:      "no reason is still parsed, so it can be reported",
			text:      "# quaddoc: disable=QD001\n[Container]\n",
			wantRules: []string{"QD001"}, wantReason: "", wantCount: 1,
		},
		{
			name:      "an ordinary comment is not a directive",
			text:      "# just a comment about QD001\n[Container]\n",
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseSuppressions("web.container", tt.text)

			if len(got) != tt.wantCount {
				t.Fatalf("suppressions = %d, want %d: %+v", len(got), tt.wantCount, got)
			}
			if tt.wantCount == 0 {
				return
			}
			if len(got[0].Rules) != len(tt.wantRules) {
				t.Errorf("rules = %v, want %v", got[0].Rules, tt.wantRules)
			}
			if tt.wantReason != "" && got[0].Reason != tt.wantReason {
				t.Errorf("reason = %q, want %q", got[0].Reason, tt.wantReason)
			}
		})
	}
}

func TestApplySuppressionsNeedsAReason(t *testing.T) {
	// A suppression whose justification has been lost is indistinguishable
	// from a bug someone gave up on, so an unreasoned one suppresses nothing
	// and is itself reported.
	findings := []rules.Finding{
		{RuleID: "QD001", Unit: "web.container", Severity: rules.Error},
	}

	cfg := &Config{Disabled: map[string]bool{}, Severity: map[string]rules.Severity{}}

	withReason := cfg.ApplySuppressions(findings, map[string][]Suppression{
		"web.container": {{Rules: []string{"QD001"}, Reason: "labelled at mount time", Line: 1}},
	})
	if len(withReason) != 0 {
		t.Errorf("a reasoned suppression should suppress the finding, got %+v", withReason)
	}

	withoutReason := cfg.ApplySuppressions(findings, map[string][]Suppression{
		"web.container": {{Rules: []string{"QD001"}, Line: 1}},
	})
	var sawOriginal, sawComplaint bool
	for _, f := range withoutReason {
		switch f.RuleID {
		case "QD001":
			sawOriginal = true
		case "QD000":
			sawComplaint = true
		}
	}
	if !sawOriginal {
		t.Error("an unreasoned suppression must not suppress anything")
	}
	if !sawComplaint {
		t.Error("an unreasoned suppression should itself be reported")
	}
}

func TestSuppressionWithoutRulesCoversEverything(t *testing.T) {
	// `# quaddoc: disable reason` with no rule list is a whole-file escape.
	s := Suppression{Reason: "generated file, reviewed elsewhere"}

	if !s.Covers("QD001") || !s.Covers("QD041") {
		t.Error("a suppression with no rule list should cover every rule")
	}
}

func TestSuppressionOnlyCoversItsRules(t *testing.T) {
	s := Suppression{Rules: []string{"QD001"}, Reason: "deliberate"}

	if !s.Covers("QD001") {
		t.Error("should cover its own rule")
	}
	if s.Covers("QD041") {
		t.Error("should not cover an unrelated rule")
	}
}

func TestStripComment(t *testing.T) {
	tests := map[string]string{
		`"warning"`:             `"warning"`,
		`"warning" # a comment`: `"warning" `,
		`"a # hash" # comment`:  `"a # hash" `,
	}
	for in, want := range tests {
		if got := stripComment(in); got != want {
			t.Errorf("stripComment(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestQD000HonoursASeverityOverride(t *testing.T) {
	// QD000 is raised here rather than by the rule engine, so it does not get
	// the engine's central override handling and has to apply it itself. It
	// previously hardcoded Warning, which meant a project could not raise
	// unreasoned suppressions to an error and gate on them.
	byUnit := map[string][]Suppression{
		"web.container": {{Rules: []string{"QD001"}, Line: 1}},
	}

	cfg := &Config{
		Disabled: map[string]bool{},
		Severity: map[string]rules.Severity{"QD000": rules.Error},
	}

	var found bool
	for _, f := range cfg.ApplySuppressions(nil, byUnit) {
		if f.RuleID != "QD000" {
			continue
		}
		found = true
		if f.Severity != rules.Error {
			t.Errorf("severity = %v, want Error after the override", f.Severity)
		}
		if f.SeverityJS != "error" {
			t.Errorf("JSON severity = %q, want \"error\"", f.SeverityJS)
		}
	}
	if !found {
		t.Fatal("QD000 was not reported")
	}
}

func TestUnreasonedSuppressionsAreReportedDeterministically(t *testing.T) {
	// Iterating the map directly made the order depend on Go's map
	// randomisation, which shows up as spurious diffs in JSON and SARIF
	// output.
	byUnit := map[string][]Suppression{
		"z.container": {{Rules: []string{"QD001"}, Line: 1}},
		"a.container": {{Rules: []string{"QD001"}, Line: 1}},
		"m.container": {{Rules: []string{"QD001"}, Line: 1}},
	}
	cfg := &Config{Disabled: map[string]bool{}, Severity: map[string]rules.Severity{}}

	var first []string
	for i := 0; i < 20; i++ {
		var order []string
		for _, f := range cfg.ApplySuppressions(nil, byUnit) {
			order = append(order, f.Unit)
		}
		if i == 0 {
			first = order
			continue
		}
		if strings.Join(order, ",") != strings.Join(first, ",") {
			t.Fatalf("order varies between runs: %v then %v", first, order)
		}
	}
	if len(first) != 3 || first[0] != "a.container" {
		t.Errorf("expected units sorted, got %v", first)
	}
}

func TestQD000CanBeDisabled(t *testing.T) {
	// QD000 is raised outside the rule engine, so it misses the engine's
	// central handling of both halves of a rule's configuration. The severity
	// override was fixed first; disabling was still ignored, which is the same
	// bug wearing a different hat.
	byUnit := map[string][]Suppression{
		"web.container": {{Rules: []string{"QD001"}, Line: 1}},
	}

	enabled := &Config{Disabled: map[string]bool{}, Severity: map[string]rules.Severity{}}
	if got := len(enabled.ApplySuppressions(nil, byUnit)); got == 0 {
		t.Fatal("QD000 should be reported when it is enabled")
	}

	disabled := &Config{
		Disabled: map[string]bool{"QD000": true},
		Severity: map[string]rules.Severity{},
	}
	for _, f := range disabled.ApplySuppressions(nil, byUnit) {
		if f.RuleID == "QD000" {
			t.Errorf("QD000 was reported despite being disabled: %+v", f)
		}
	}
}

func TestDisablingQD000DoesNotAffectSuppression(t *testing.T) {
	// Turning off the complaint about a missing reason must not make an
	// unreasoned directive start working. The reason is still mandatory; the
	// project has only asked not to be told about it.
	findings := []rules.Finding{{RuleID: "QD001", Unit: "web.container", Severity: rules.Error}}
	byUnit := map[string][]Suppression{
		"web.container": {{Rules: []string{"QD001"}, Line: 1}},
	}

	cfg := &Config{
		Disabled: map[string]bool{"QD000": true},
		Severity: map[string]rules.Severity{},
	}

	var sawOriginal bool
	for _, f := range cfg.ApplySuppressions(findings, byUnit) {
		if f.RuleID == "QD001" {
			sawOriginal = true
		}
	}
	if !sawOriginal {
		t.Error("an unreasoned suppression must still suppress nothing, even with QD000 off")
	}
}
