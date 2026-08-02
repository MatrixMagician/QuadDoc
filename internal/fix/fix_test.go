package fix

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MatrixMagician/quaddoc/internal/hostctx"
	"github.com/MatrixMagician/quaddoc/internal/ir"
	"github.com/MatrixMagician/quaddoc/internal/rules"
)

// writeUnits creates a directory of unit files and loads it as a project.
func writeUnits(t *testing.T, units map[string]string) (string, *ir.Project) {
	t.Helper()
	dir := t.TempDir()

	for name, body := range units {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatalf("writing %s: %v", name, err)
		}
	}

	project, err := ir.LoadProject(dir)
	if err != nil {
		t.Fatalf("loading project: %v", err)
	}
	return dir, project
}

// fixOnce runs lint then fix over a directory, writing the result.
func fixOnce(t *testing.T, dir string, opts Options) *Result {
	t.Helper()

	project, err := ir.LoadProject(dir)
	if err != nil {
		t.Fatalf("loading project: %v", err)
	}

	engine := &rules.Engine{Host: hostctx.Static{SELinuxMode: hostctx.SELinuxEnforcing}}
	findings := engine.Run(project)

	result, err := Apply(project, findings, opts)
	if err != nil {
		t.Fatalf("applying fixes: %v", err)
	}
	if err := Write(result); err != nil {
		t.Fatalf("writing fixes: %v", err)
	}
	return result
}

// snapshot reads every file in a directory, for comparing before and after.
func snapshot(t *testing.T, dir string) map[string]string {
	t.Helper()

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading %s: %v", dir, err)
	}

	out := map[string]string{}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatalf("reading %s: %v", e.Name(), err)
		}
		out[e.Name()] = string(data)
	}
	return out
}

// TestFixIsIdempotent is load-bearing: without it, running quaddoc in CI would
// produce a fresh diff on every run.
func TestFixIsIdempotent(t *testing.T) {
	cases := []struct {
		name  string
		units map[string]string
	}{
		{
			name: "missing install section",
			units: map[string]string{
				"web.container": "[Container]\nImage=docker.io/library/nginx:1.27\n",
			},
		},
		{
			name: "unlabelled private bind mount",
			units: map[string]string{
				"web.container": "[Container]\nImage=docker.io/library/nginx:1.27\n" +
					"Volume=/srv/site:/data\n[Install]\nWantedBy=default.target\n",
			},
		},
		{
			name: "unlabelled shared bind mount",
			units: map[string]string{
				"a.container": "[Container]\nImage=docker.io/library/nginx:1.27\n" +
					"Volume=/srv/shared:/data\n[Install]\nWantedBy=default.target\n",
				"b.container": "[Container]\nImage=docker.io/library/postgres:16\n" +
					"Volume=/srv/shared:/data\n[Install]\nWantedBy=default.target\n",
			},
		},
		{
			name: "missing shared network",
			units: map[string]string{
				"a.container": "[Container]\nImage=docker.io/library/nginx:1.27\n" +
					"[Install]\nWantedBy=default.target\n",
				"b.container": "[Container]\nImage=docker.io/library/postgres:16\n" +
					"[Install]\nWantedBy=default.target\n",
			},
		},
		{
			name: "everything at once",
			units: map[string]string{
				"a.container": "[Container]\nImage=docker.io/library/nginx:1.27\nVolume=/srv/s:/data\n",
				"b.container": "[Container]\nImage=docker.io/library/postgres:16\nVolume=/srv/s:/backup\n",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir, _ := writeUnits(t, tc.units)

			fixOnce(t, dir, Options{})
			after := snapshot(t, dir)

			fixOnce(t, dir, Options{})
			again := snapshot(t, dir)

			if len(after) != len(again) {
				t.Fatalf("the second run changed the file set: %d then %d", len(after), len(again))
			}
			for name, content := range after {
				if again[name] != content {
					t.Errorf("%s changed on the second run:\n--- once ---\n%s\n--- twice ---\n%s",
						name, content, again[name])
				}
			}
		})
	}
}

// TestFixLeavesUntouchedBytesAlone is why the parser preserves original text.
func TestFixLeavesUntouchedBytesAlone(t *testing.T) {
	original := `# A comment that must survive.
; And a semicolon comment.

[Unit]
Description=Web front end

[Container]
Image=docker.io/library/nginx:1.27
# An explanatory comment above the mount.
Volume=/srv/site:/data
Environment=A=1   B=2
PodmanArgs=--label \
  app=web
`
	dir, _ := writeUnits(t, map[string]string{"web.container": original})
	fixOnce(t, dir, Options{})

	after := snapshot(t, dir)["web.container"]

	for _, line := range []string{
		"# A comment that must survive.",
		"; And a semicolon comment.",
		"Description=Web front end",
		"# An explanatory comment above the mount.",
		"Environment=A=1   B=2",
		"PodmanArgs=--label \\",
		"  app=web",
	} {
		if !strings.Contains(after, line) {
			t.Errorf("the fix disturbed %q:\n%s", line, after)
		}
	}
}

// TestFixedUnitsStillPassTheGenerator is the check that matters most: a fix
// that produced a file Podman rejects would be worse than no fix at all.
func TestFixedUnitsStillPassTheGenerator(t *testing.T) {
	generator := quadletGenerator(t)

	dir, _ := writeUnits(t, map[string]string{
		"a.container": "[Container]\nImage=docker.io/library/nginx:1.27\nVolume=/srv/s:/data\n",
		"b.container": "[Container]\nImage=docker.io/library/postgres:16\nVolume=/srv/s:/backup\n",
	})
	fixOnce(t, dir, Options{})

	cmd := exec.Command(generator, "-dryrun", "-user")
	cmd.Env = append(os.Environ(), "QUADLET_UNIT_DIRS="+dir)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("the generator rejected the fixed units: %v\n%s", err, out)
	}
}

// TestFixResolvesTheFindings closes the loop: after fixing, the rules that
// prompted the fix should no longer fire.
func TestFixResolvesTheFindings(t *testing.T) {
	dir, _ := writeUnits(t, map[string]string{
		"a.container": "[Container]\nImage=docker.io/library/nginx:1.27\nVolume=/srv/s:/data\n",
		"b.container": "[Container]\nImage=docker.io/library/postgres:16\nVolume=/srv/s:/backup\n",
	})
	fixOnce(t, dir, Options{})

	project, err := ir.LoadProject(dir)
	if err != nil {
		t.Fatalf("reloading: %v", err)
	}
	engine := &rules.Engine{Host: hostctx.Static{SELinuxMode: hostctx.SELinuxEnforcing}}

	for _, f := range engine.Run(project) {
		switch f.RuleID {
		case "QD001", "QD022", "QD030":
			t.Errorf("%s still fires after being fixed: %s", f.RuleID, f.Message)
		}
	}
}

// TestFixUsesTheOptionTheRuleChose is the F3 guard extended to the fix engine.
//
// The rule picks :z or :Z using the project-wide sharing map. If the fix
// re-derived it, or defaulted, it could write a :Z that QD002 then flags, which
// would be the same contradiction in a new place.
func TestFixUsesTheOptionTheRuleChose(t *testing.T) {
	dir, _ := writeUnits(t, map[string]string{
		"a.container": "[Container]\nImage=nginx\nVolume=/srv/shared:/data\n" +
			"[Install]\nWantedBy=default.target\n",
		"b.container": "[Container]\nImage=postgres\nVolume=/srv/shared:/data\n" +
			"[Install]\nWantedBy=default.target\n",
		"c.container": "[Container]\nImage=redis\nVolume=/srv/private:/data\n" +
			"[Install]\nWantedBy=default.target\n",
	})
	fixOnce(t, dir, Options{})
	after := snapshot(t, dir)

	// The shared source must get :z in both units.
	for _, name := range []string{"a.container", "b.container"} {
		if !strings.Contains(after[name], "/srv/shared:/data:z") {
			t.Errorf("%s should have the shared label:\n%s", name, after[name])
		}
	}
	// The private source must get :Z.
	if !strings.Contains(after["c.container"], "/srv/private:/data:Z") {
		t.Errorf("c.container should have the private label:\n%s", after["c.container"])
	}
}

func TestFixOnlyTouchesRequestedRules(t *testing.T) {
	dir, _ := writeUnits(t, map[string]string{
		"web.container": "[Container]\nImage=docker.io/library/nginx:1.27\nVolume=/srv/site:/data\n",
	})
	fixOnce(t, dir, Options{Only: map[string]bool{"QD001": true}})

	after := snapshot(t, dir)["web.container"]
	if !strings.Contains(after, ":Z") {
		t.Errorf("QD001 was requested but not applied:\n%s", after)
	}
	if strings.Contains(after, "[Install]") {
		t.Errorf("QD022 was applied despite not being requested:\n%s", after)
	}
}

func TestUnfixableFindingsAreReportedNotSilentlyDropped(t *testing.T) {
	// QD002 has no safe fix, because choosing between relaxing the label and
	// separating the directories is a decision about intent. The user must be
	// told rather than left thinking the fix run cleaned everything.
	dir, _ := writeUnits(t, map[string]string{
		"a.container": "[Container]\nImage=nginx\nVolume=/srv/shared:/data:Z\n" +
			"Network=x.network\n[Install]\nWantedBy=default.target\n",
		"b.container": "[Container]\nImage=postgres\nVolume=/srv/shared:/data:Z\n" +
			"Network=x.network\n[Install]\nWantedBy=default.target\n",
		"x.network": "[Network]\n",
	})

	project, err := ir.LoadProject(dir)
	if err != nil {
		t.Fatalf("loading: %v", err)
	}
	engine := &rules.Engine{Host: hostctx.Static{SELinuxMode: hostctx.SELinuxEnforcing}}
	result, err := Apply(project, engine.Run(project), Options{})
	if err != nil {
		t.Fatalf("applying: %v", err)
	}

	var sawQD002 bool
	for _, f := range result.Unfixed {
		if f.RuleID == "QD002" {
			sawQD002 = true
		}
	}
	if !sawQD002 {
		t.Errorf("QD002 should be reported as unfixed, got %+v", result.Unfixed)
	}
}

func TestDiffShowsAdditionsAndContext(t *testing.T) {
	change := Change{
		Path:   "web.container",
		Before: "[Container]\nImage=nginx\n",
		After:  "[Container]\nImage=nginx\nNetwork=shared.network\n",
	}

	diff := Diff(change)
	if !strings.Contains(diff, "+Network=shared.network") {
		t.Errorf("diff does not show the addition:\n%s", diff)
	}
	if !strings.Contains(diff, " [Container]") {
		t.Errorf("diff does not show context:\n%s", diff)
	}
	if !strings.Contains(diff, "--- web.container") {
		t.Errorf("diff has no header:\n%s", diff)
	}
}

func TestDiffOfACreatedFileReadsAsNew(t *testing.T) {
	change := Change{Path: "shared.network", After: "[Network]\n", Created: true}

	diff := Diff(change)
	if !strings.Contains(diff, "--- /dev/null") {
		t.Errorf("a created file should diff against /dev/null:\n%s", diff)
	}
}

func TestAppendOption(t *testing.T) {
	tests := []struct {
		value  string
		option string
		want   string
	}{
		{value: "/srv:/data", option: "Z", want: "/srv:/data:Z"},
		{value: "/srv:/data:ro", option: "Z", want: "/srv:/data:ro,Z"},
		{value: "/srv:/data:ro,U", option: "z", want: "/srv:/data:ro,U,z"},
	}
	for _, tt := range tests {
		t.Run(tt.value, func(t *testing.T) {
			if got := appendOption(tt.value, tt.option); got != tt.want {
				t.Errorf("appendOption(%q, %q) = %q, want %q", tt.value, tt.option, got, tt.want)
			}
		})
	}
}

func TestHasLabelOption(t *testing.T) {
	tests := map[string]bool{
		"/srv:/data":      false,
		"/srv:/data:ro":   false,
		"/srv:/data:Z":    true,
		"/srv:/data:z":    true,
		"/srv:/data:ro,Z": true,
		"/srv:/data:ro,U": false,
	}
	for value, want := range tests {
		if got := hasLabelOption(value); got != want {
			t.Errorf("hasLabelOption(%q) = %v, want %v", value, got, want)
		}
	}
}

func TestFileWithoutTrailingNewlineKeepsItsShape(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "web.container")
	if err := os.WriteFile(path, []byte("[Container]\nImage=nginx"), 0o644); err != nil {
		t.Fatalf("writing: %v", err)
	}

	fixOnce(t, dir, Options{})

	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading: %v", err)
	}
	if strings.HasSuffix(string(after), "\n") {
		t.Errorf("a file with no trailing newline gained one:\n%q", string(after))
	}
}

// TestFixQD001GuardsAgainstDoubleLabelling exercises the idempotence guard in
// fixQD001 directly.
//
// End-to-end idempotence holds for a different reason: once a mount is
// labelled, QD001 stops firing, so the fix is never reached a second time.
// That makes the guard defence in depth, and defence in depth that no test
// exercises is just untested code. This calls the fix with a finding that
// points at an already-labelled line, which is what would happen if a rule
// were ever loosened.
func TestFixQD001GuardsAgainstDoubleLabelling(t *testing.T) {
	tests := []struct {
		name    string
		line    string
		option  string
		wantHit bool
	}{
		{
			name: "an unlabelled mount is labelled",
			line: "Volume=/srv/site:/data", option: "Z", wantHit: true,
		},
		{
			name: "an already private-labelled mount is left alone",
			line: "Volume=/srv/site:/data:Z", option: "Z", wantHit: false,
		},
		{
			name: "an already shared-labelled mount is left alone",
			line: "Volume=/srv/site:/data:z", option: "z", wantHit: false,
		},
		{
			name: "a label alongside other options is still detected",
			line: "Volume=/srv/site:/data:ro,Z", option: "Z", wantHit: false,
		},
		{
			// Applying the opposite label would produce `:Z,z`, which is
			// contradictory and would be Podman's problem, not ours.
			name: "the opposite label is not added on top",
			line: "Volume=/srv/site:/data:Z", option: "z", wantHit: false,
		},
		{
			name: "a non-Volume line is never touched",
			line: "Image=docker.io/library/nginx:1.27", option: "Z", wantHit: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lines := []string{"[Container]", tt.line}
			finding := rules.Finding{
				RuleID: "QD001", Line: 2,
				Fix: map[string]string{"option": tt.option},
			}

			got, changed := fixQD001(lines, finding)
			if changed != tt.wantHit {
				t.Fatalf("changed = %v, want %v (line became %q)", changed, tt.wantHit, got[1])
			}
			if !tt.wantHit && got[1] != tt.line {
				t.Errorf("an untouched line was modified: %q -> %q", tt.line, got[1])
			}
		})
	}
}

// TestFixQD001IsIdempotentWhenCalledTwice applies the same finding twice
// directly, which the end-to-end test cannot do because the rule stops firing.
func TestFixQD001IsIdempotentWhenCalledTwice(t *testing.T) {
	lines := []string{"[Container]", "Volume=/srv/site:/data"}
	finding := rules.Finding{RuleID: "QD001", Line: 2, Fix: map[string]string{"option": "Z"}}

	once, _ := fixQD001(lines, finding)
	first := once[1]

	twice, changed := fixQD001(once, finding)
	if changed {
		t.Error("the second application reported a change")
	}
	if twice[1] != first {
		t.Errorf("applying twice differs from applying once: %q then %q", first, twice[1])
	}
}

// TestFixQD022GuardsAgainstDuplicateInstall likewise exercises QD022's guard
// directly, since the rule also stops firing after the first fix.
func TestFixQD022GuardsAgainstDuplicateInstall(t *testing.T) {
	withInstall := []string{"[Container]", "Image=nginx", "", "[Install]", "WantedBy=default.target"}

	got, changed := fixQD022(withInstall)
	if changed {
		t.Errorf("a unit that already has [Install] was modified: %v", got)
	}

	// An empty [Install] should gain the key rather than a second section.
	empty := []string{"[Container]", "Image=nginx", "", "[Install]"}
	got, changed = fixQD022(empty)
	if !changed {
		t.Fatal("an empty [Install] should be filled in")
	}
	if count := countOccurrences(got, "[Install]"); count != 1 {
		t.Errorf("expected one [Install] section, got %d: %v", count, got)
	}

	// Applying again must not add a second key.
	again, changed := fixQD022(got)
	if changed {
		t.Errorf("the second application changed the file: %v", again)
	}
}

// TestFixQD030GuardsAgainstDuplicateNetwork covers the third fixable rule.
func TestFixQD030GuardsAgainstDuplicateNetwork(t *testing.T) {
	lines := []string{"[Container]", "Image=nginx"}

	once, changed := fixQD030(lines, "shared")
	if !changed {
		t.Fatal("the network key should have been added")
	}
	if count := countOccurrences(once, "Network=shared.network"); count != 1 {
		t.Fatalf("expected one Network= key, got %d: %v", count, once)
	}

	twice, changed := fixQD030(once, "shared")
	if changed {
		t.Error("the second application reported a change")
	}
	if count := countOccurrences(twice, "Network=shared.network"); count != 1 {
		t.Errorf("applying twice produced %d Network= keys: %v", count, twice)
	}
}

func countOccurrences(lines []string, want string) int {
	n := 0
	for _, line := range lines {
		if strings.TrimSpace(line) == want {
			n++
		}
	}
	return n
}
