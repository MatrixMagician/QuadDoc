package rules

import (
	"strings"
	"testing"

	"github.com/MatrixMagician/quaddoc/internal/hostctx"
	"github.com/MatrixMagician/quaddoc/internal/ir"
	"github.com/MatrixMagician/quaddoc/internal/parse/quadlet"
)

// unitFromText builds a unit from unit-file text, so tests read like the files
// users actually write rather than like IR literals.
func unitFromText(t *testing.T, name, text string) *ir.Unit {
	t.Helper()
	f, err := quadlet.Parse(name, strings.NewReader(text))
	if err != nil {
		t.Fatalf("parsing %s: %v", name, err)
	}
	return ir.FromParsed(f)
}

// runRule runs one rule over a project built from the given units.
func runRule(t *testing.T, ruleID string, host hostctx.Context, units ...*ir.Unit) []Finding {
	t.Helper()
	p := &ir.Project{Units: units}
	p.Sort()

	e := &Engine{Host: host}
	all := e.Run(p)

	var out []Finding
	for _, f := range all {
		if f.RuleID == ruleID {
			out = append(out, f)
		}
	}
	return out
}

func TestQD022(t *testing.T) {
	tests := []struct {
		name         string
		unit         string
		text         string
		wantFindings int
		wantSeverity Severity
	}{
		{
			name:         "container with no [Install] never autostarts",
			unit:         "web.container",
			text:         "[Container]\nImage=docker.io/library/nginx:1.27\n",
			wantFindings: 1, wantSeverity: Error,
		},
		{
			name: "container with [Install] is fine",
			unit: "web.container",
			text: "[Container]\nImage=docker.io/library/nginx:1.27\n" +
				"[Install]\nWantedBy=default.target\n",
			wantFindings: 0,
		},
		{
			name:         "an empty [Install] still never autostarts",
			unit:         "web.container",
			text:         "[Container]\nImage=docker.io/library/nginx:1.27\n[Install]\n",
			wantFindings: 1, wantSeverity: Error,
		},
		{
			name: "a one-shot is a note, not an error",
			unit: "job.container",
			text: "[Container]\nImage=docker.io/library/alpine:3.20\n" +
				"[Service]\nRestart=no\n",
			wantFindings: 1, wantSeverity: Note,
		},
		{
			// Verified against Podman 5.8.4: the pod service gets
			// `Wants=app.service`, so a pod member is started with the pod
			// and carries no [Install] of its own.
			name:         "a pod member needs no [Install] of its own",
			unit:         "app.container",
			text:         "[Container]\nImage=docker.io/library/nginx:1.27\nPod=demo.pod\n",
			wantFindings: 0,
		},
		{
			name:         "volume units need no [Install]",
			unit:         "pgdata.volume",
			text:         "[Volume]\n",
			wantFindings: 0,
		},
		{
			name:         "network units need no [Install]",
			unit:         "app.network",
			text:         "[Network]\n",
			wantFindings: 0,
		},
		{
			name:         "a pod itself does need an [Install]",
			unit:         "demo.pod",
			text:         "[Pod]\nPodName=demo\n",
			wantFindings: 1, wantSeverity: Error,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := unitFromText(t, tt.unit, tt.text)
			got := runRule(t, "QD022", hostctx.Unknown{}, u)

			if len(got) != tt.wantFindings {
				t.Fatalf("findings = %d, want %d: %+v", len(got), tt.wantFindings, got)
			}
			if tt.wantFindings > 0 && got[0].Severity != tt.wantSeverity {
				t.Errorf("severity = %v, want %v", got[0].Severity, tt.wantSeverity)
			}
		})
	}
}

func TestQD022RemediationIsCopyPasteable(t *testing.T) {
	// Every finding must carry something the user can act on: the whole point
	// of the tool is that it explains rather than merely complains.
	u := unitFromText(t, "web.container", "[Container]\nImage=nginx\n")
	got := runRule(t, "QD022", hostctx.Unknown{}, u)

	if len(got) != 1 {
		t.Fatalf("findings = %d, want 1", len(got))
	}
	if !strings.Contains(got[0].Remediation, "[Install]") ||
		!strings.Contains(got[0].Remediation, "WantedBy=") {
		t.Errorf("remediation is not copy-pasteable: %q", got[0].Remediation)
	}
}

func TestQD023(t *testing.T) {
	tests := []struct {
		name         string
		text         string
		wantFindings int
	}{
		{
			name: "the four honoured keys are accepted",
			text: "[Container]\nImage=nginx\n[Install]\n" +
				"WantedBy=default.target\nRequiredBy=other.service\n" +
				"Alias=web.service\nUpheldBy=some.service\n",
			wantFindings: 0,
		},
		{
			name: "an unhonoured key is reported",
			text: "[Container]\nImage=nginx\n[Install]\n" +
				"WantedBy=default.target\nAlso=extra.service\n",
			wantFindings: 1,
		},
		{
			name:         "matching is case-insensitive, as systemd is",
			text:         "[Container]\nImage=nginx\n[Install]\nwantedby=default.target\n",
			wantFindings: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := unitFromText(t, "web.container", tt.text)
			got := runRule(t, "QD023", hostctx.Unknown{}, u)

			if len(got) != tt.wantFindings {
				t.Fatalf("findings = %d, want %d: %+v", len(got), tt.wantFindings, got)
			}
		})
	}
}

func TestExitCode(t *testing.T) {
	tests := []struct {
		name     string
		findings []Finding
		want     int
	}{
		{name: "no findings is clean", findings: nil, want: 0},
		{name: "notes alone do not fail", findings: []Finding{{Severity: Note}}, want: 0},
		{name: "warnings exit 1", findings: []Finding{{Severity: Warning}}, want: 1},
		{name: "errors exit 2", findings: []Finding{{Severity: Error}}, want: 2},
		{
			name:     "the worst severity wins",
			findings: []Finding{{Severity: Note}, {Severity: Error}, {Severity: Warning}},
			want:     2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ExitCode(tt.findings); got != tt.want {
				t.Errorf("ExitCode = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestSeverityOverride(t *testing.T) {
	// A project may decide a rule matters less to it than the default.
	u := unitFromText(t, "web.container", "[Container]\nImage=nginx\n")
	p := &ir.Project{Units: []*ir.Unit{u}}

	e := &Engine{
		Host:   hostctx.Unknown{},
		Config: Config{SeverityOverride: map[string]Severity{"QD022": Note}},
	}
	for _, f := range e.Run(p) {
		if f.RuleID == "QD022" && f.Severity != Note {
			t.Errorf("severity = %v, want Note after override", f.Severity)
		}
	}
}

func TestDisabledRuleDoesNotRun(t *testing.T) {
	u := unitFromText(t, "web.container", "[Container]\nImage=nginx\n")
	p := &ir.Project{Units: []*ir.Unit{u}}

	e := &Engine{Host: hostctx.Unknown{}, Config: Config{Disabled: map[string]bool{"QD022": true}}}
	for _, f := range e.Run(p) {
		if f.RuleID == "QD022" {
			t.Error("QD022 ran despite being disabled")
		}
	}
}

func TestFindingsAreDeterministicallyOrdered(t *testing.T) {
	// Output that depends on map iteration order makes golden files flaky and
	// diffs meaningless.
	units := []*ir.Unit{
		unitFromText(t, "z.container", "[Container]\nImage=nginx\n"),
		unitFromText(t, "a.container", "[Container]\nImage=nginx\n"),
		unitFromText(t, "m.container", "[Container]\nImage=nginx\n"),
	}

	var first []string
	for i := 0; i < 20; i++ {
		p := &ir.Project{Units: units}
		p.Sort()
		e := &Engine{Host: hostctx.Unknown{}}

		var order []string
		for _, f := range e.Run(p) {
			order = append(order, f.Unit+"/"+f.RuleID)
		}
		if i == 0 {
			first = order
			continue
		}
		if strings.Join(order, ",") != strings.Join(first, ",") {
			t.Fatalf("ordering varies between runs:\n  %v\n  %v", first, order)
		}
	}
}

func TestEveryRuleHasMetadata(t *testing.T) {
	// The reference documentation is generated from this metadata, so a rule
	// missing any of it ships a blank entry. Register panics on a missing
	// citation; the rest is checked here.
	for _, r := range All() {
		if r.Summary == "" {
			t.Errorf("%s has no summary", r.ID)
		}
		if r.Rationale == "" {
			t.Errorf("%s has no rationale", r.ID)
		}
		if r.Citation == "" {
			t.Errorf("%s has no citation", r.ID)
		}
	}
}

func TestEveryFindingCarriesRemediation(t *testing.T) {
	// A finding without a remediation is a bug in the rule: the tool exists to
	// say what to do, not merely that something is wrong.
	u := unitFromText(t, "web.container",
		"[Container]\nImage=nginx\n[Install]\nAlso=bad.service\n")
	p := &ir.Project{Units: []*ir.Unit{u}}

	e := &Engine{Host: hostctx.Unknown{}}
	found := e.Run(p)
	if len(found) == 0 {
		t.Fatal("expected findings to check")
	}
	for _, f := range found {
		if strings.TrimSpace(f.Remediation) == "" {
			t.Errorf("%s produced a finding with no remediation", f.RuleID)
		}
		if strings.TrimSpace(f.Message) == "" {
			t.Errorf("%s produced a finding with no message", f.RuleID)
		}
	}
}

func TestSELinuxDowngradeLadder(t *testing.T) {
	// ADR-0004: enforcing keeps the default, permissive drops to a note
	// because enabling enforcing later would break the container, and absent
	// suppresses the finding entirely.
	tests := []struct {
		mode     hostctx.SELinuxMode
		want     Severity
		wantKeep bool
	}{
		{hostctx.SELinuxEnforcing, Error, true},
		{hostctx.SELinuxPermissive, Note, true},
		{hostctx.SELinuxDisabled, Note, false},
		{hostctx.SELinuxUnknown, Error, true},
	}
	for _, tt := range tests {
		t.Run(tt.mode.String(), func(t *testing.T) {
			got, keep := DowngradeForSELinux(tt.mode, Error)
			if got != tt.want || keep != tt.wantKeep {
				t.Errorf("DowngradeForSELinux(%v, Error) = %v, %v; want %v, %v",
					tt.mode, got, keep, tt.want, tt.wantKeep)
			}
		})
	}
}
