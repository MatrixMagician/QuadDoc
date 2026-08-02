package output

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/MatrixMagician/quaddoc/internal/rules"
)

var update = flag.Bool("update", false, "rewrite golden files")

// sample is a fixed set of findings covering every severity, a finding with and
// without a line, and a multi-line remediation.
func sample() []rules.Finding {
	return []rules.Finding{
		{
			RuleID: "QD022", Severity: rules.Error, SeverityJS: "error",
			Confidence: rules.Confirmed, Unit: "units/web.container",
			Message:     "web has no [Install] section, so it will never start automatically",
			Remediation: "Add an [Install] section:\n\n    [Install]\n    WantedBy=default.target",
		},
		{
			RuleID: "QD001", Severity: rules.Warning, SeverityJS: "warning",
			Confidence: rules.Possible, Unit: "units/web.container", Line: 4,
			Message:     "bind mount /srv/site has no SELinux relabelling option",
			Remediation: "Append :Z to the mount.",
		},
		{
			RuleID: "QD021", Severity: rules.Note, SeverityJS: "note",
			Confidence: rules.Confirmed, Unit: "units/db.container", Line: 9,
			Message:     "restart policy unless-stopped has no exact systemd equivalent",
			Remediation: "Use Restart=always with an [Install] section.",
		},
	}
}

// golden compares output against a checked-in file, rewriting it under -update.
func golden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", name)

	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatalf("creating testdata: %v", err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatalf("writing golden: %v", err)
		}
		return
	}

	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading golden %s (run with -update to create it): %v", path, err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("output differs from %s.\n--- got ---\n%s\n--- want ---\n%s", path, got, want)
	}
}

func TestHumanGolden(t *testing.T) {
	var buf bytes.Buffer
	// Colour off: golden files should not carry escape sequences.
	Human{Colour: false}.Render(&buf, sample())
	golden(t, "human.txt", buf.Bytes())
}

func TestHumanEmptyIsReassuring(t *testing.T) {
	var buf bytes.Buffer
	Human{}.Render(&buf, nil)

	if got := buf.String(); got != "No problems found.\n" {
		t.Errorf("empty render = %q", got)
	}
}

func TestHumanOutputHasNoTrailingWhitespace(t *testing.T) {
	// Trailing whitespace shows up in diffs and in golden files, and is a
	// common source of spurious churn.
	var buf bytes.Buffer
	Human{Colour: false}.Render(&buf, sample())

	for i, line := range bytes.Split(buf.Bytes(), []byte("\n")) {
		if len(line) > 0 && (line[len(line)-1] == ' ' || line[len(line)-1] == '\t') {
			t.Errorf("line %d has trailing whitespace: %q", i+1, line)
		}
	}
}

func TestJSONGolden(t *testing.T) {
	var buf bytes.Buffer
	if err := JSON(&buf, sample()); err != nil {
		t.Fatalf("JSON: %v", err)
	}
	golden(t, "report.json", buf.Bytes())
}

func TestJSONIsValidAndCountsSeverities(t *testing.T) {
	var buf bytes.Buffer
	if err := JSON(&buf, sample()); err != nil {
		t.Fatalf("JSON: %v", err)
	}

	var report Report
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if report.Version != SchemaVersion {
		t.Errorf("version = %d, want %d", report.Version, SchemaVersion)
	}
	if report.Summary.Errors != 1 || report.Summary.Warnings != 1 || report.Summary.Notes != 1 {
		t.Errorf("summary = %+v, want 1 of each", report.Summary)
	}
}

func TestJSONEmptyFindingsIsArrayNotNull(t *testing.T) {
	// A consumer should be able to iterate without a nil check.
	var buf bytes.Buffer
	if err := JSON(&buf, nil); err != nil {
		t.Fatalf("JSON: %v", err)
	}
	if !bytes.Contains(buf.Bytes(), []byte(`"findings": []`)) {
		t.Errorf("empty findings should render as [], got:\n%s", buf.String())
	}
}

func TestJSONCarriesConfidence(t *testing.T) {
	// The distinction between a possibility and a confirmed fact is part of
	// the contract, so it must survive serialisation.
	var buf bytes.Buffer
	if err := JSON(&buf, sample()); err != nil {
		t.Fatalf("JSON: %v", err)
	}

	var report Report
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	var sawPossible, sawConfirmed bool
	for _, f := range report.Findings {
		switch f.Confidence {
		case rules.Possible:
			sawPossible = true
		case rules.Confirmed:
			sawConfirmed = true
		}
	}
	if !sawPossible || !sawConfirmed {
		t.Error("confidence did not survive serialisation")
	}
}

func TestColourDisabledByNoColor(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	if ColourEnabled(os.Stdout) {
		t.Error("NO_COLOR must disable colour (https://no-color.org)")
	}
}

func TestColourDisabledForNonTerminal(t *testing.T) {
	var buf bytes.Buffer
	if ColourEnabled(&buf) {
		t.Error("colour must be off when the destination is not a terminal")
	}
}
