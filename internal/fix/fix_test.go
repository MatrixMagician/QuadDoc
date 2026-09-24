package fix

import (
	"github.com/MatrixMagician/quaddoc/internal/podmantest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MatrixMagician/quaddoc/internal/hostctx"
	"github.com/MatrixMagician/quaddoc/internal/ir"
	"github.com/MatrixMagician/quaddoc/internal/parse/quadlet"
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
	generator := podmantest.Generator(t)

	dir, _ := writeUnits(t, map[string]string{
		"a.container": "[Container]\nImage=docker.io/library/nginx:1.27\nVolume=/srv/s:/data\n",
		"b.container": "[Container]\nImage=docker.io/library/postgres:16\nVolume=/srv/s:/backup\n",
	})
	fixOnce(t, dir, Options{})

	podmantest.AssertAccepts(t, generator, dir)
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
			lines := parseLines(t, "[Container]", tt.line)
			finding := rules.Finding{
				RuleID: "QD001", Line: 2,
				Fix: map[string]string{"option": tt.option},
			}

			got, changed := fixQD001(lines, finding)
			if changed != tt.wantHit {
				t.Fatalf("changed = %v, want %v (line became %q)", changed, tt.wantHit, got[1].Raw)
			}
			if !tt.wantHit && got[1].Raw[0] != tt.line {
				t.Errorf("an untouched line was modified: %q -> %q", tt.line, got[1].Raw)
			}
		})
	}
}

// TestFixQD001IsIdempotentWhenCalledTwice applies the same finding twice
// directly, which the end-to-end test cannot do because the rule stops firing.
func TestFixQD001IsIdempotentWhenCalledTwice(t *testing.T) {
	lines := parseLines(t, "[Container]", "Volume=/srv/site:/data")
	finding := rules.Finding{RuleID: "QD001", Line: 2, Fix: map[string]string{"option": "Z"}}

	once, _ := fixQD001(lines, finding)
	first := once[1].Raw[0]

	twice, changed := fixQD001(once, finding)
	if changed {
		t.Error("the second application reported a change")
	}
	if twice[1].Raw[0] != first {
		t.Errorf("applying twice differs from applying once: %q then %q", first, twice[1].Raw[0])
	}
}

// TestFixQD022GuardsAgainstDuplicateInstall likewise exercises QD022's guard
// directly, since the rule also stops firing after the first fix.
func TestFixQD022GuardsAgainstDuplicateInstall(t *testing.T) {
	withInstall := parseLines(t, "[Container]", "Image=nginx", "", "[Install]", "WantedBy=default.target")

	got, changed := fixQD022(withInstall)
	if changed {
		t.Errorf("a unit that already has [Install] was modified: %v", got)
	}

	// An empty [Install] should gain the key rather than a second section.
	empty := parseLines(t, "[Container]", "Image=nginx", "", "[Install]")
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
	lines := parseLines(t, "[Container]", "Image=nginx")

	once, changed := fixQD030(lines, "shared", "")
	if !changed {
		t.Fatal("the network key should have been added")
	}
	if count := countOccurrences(once, "Network=shared.network"); count != 1 {
		t.Fatalf("expected one Network= key, got %d: %v", count, once)
	}

	twice, changed := fixQD030(once, "shared", "")
	if changed {
		t.Error("the second application reported a change")
	}
	if count := countOccurrences(twice, "Network=shared.network"); count != 1 {
		t.Errorf("applying twice produced %d Network= keys: %v", count, twice)
	}
}

// TestFixQD030KeepsAContinuedEntryWhole guards issue #11: the Network= key
// once landed between an Exec= line and its continuation, which Quadlet
// rejects as a line that is not a key-value pair.
func TestFixQD030KeepsAContinuedEntryWhole(t *testing.T) {
	generator := podmantest.Generator(t)

	dir, _ := writeUnits(t, map[string]string{
		"a.container": "[Container]\nImage=docker.io/library/alpine:3.20\n" +
			"Exec=/bin/sh -c \\\n  \"echo hello\"\n\n[Install]\nWantedBy=default.target\n",
		"b.container": "[Container]\nImage=docker.io/library/alpine:3.20\n\n" +
			"[Install]\nWantedBy=default.target\n",
	})
	fixOnce(t, dir, Options{})

	want := "[Container]\nImage=docker.io/library/alpine:3.20\n" +
		"Exec=/bin/sh -c \\\n  \"echo hello\"\nNetwork=shared.network\n\n" +
		"[Install]\nWantedBy=default.target\n"
	if got := snapshot(t, dir)["a.container"]; got != want {
		t.Errorf("a.container after fixing:\n%s\nwant:\n%s", got, want)
	}
	podmantest.AssertAccepts(t, generator, dir)
}

// TestFixQD030ReplacesAnOwnStackNetwork guards issue #41: the fix appended
// the shared network below Network=pasta, and Podman refuses a second network
// beside pasta, slirp4netns or private ("cannot set multiple networks without
// bridge network mode"). The generator accepts the pair, so the test pins the
// exact line. A bridge with options joins both networks, so it keeps its line.
func TestFixQD030ReplacesAnOwnStackNetwork(t *testing.T) {
	generator := podmantest.Generator(t)

	for _, tc := range []struct{ network, want string }{
		{"pasta", "Network=shared.network\n"},
		{"slirp4netns", "Network=shared.network\n"},
		{"private", "Network=shared.network\n"},
		{"Pasta:--map-gw", "Network=shared.network\n"},
		{"bridge:ip=10.88.0.10", "Network=bridge:ip=10.88.0.10\nNetwork=shared.network\n"},
	} {
		t.Run(tc.network, func(t *testing.T) {
			dir, _ := writeUnits(t, map[string]string{
				"a.container": "[Container]\nImage=docker.io/library/nginx:1.27\nNetwork=" + tc.network +
					"\n\n[Install]\nWantedBy=default.target\n",
				"b.container": "[Container]\nImage=docker.io/library/nginx:1.27\n\n" +
					"[Install]\nWantedBy=default.target\n",
			})
			fixOnce(t, dir, Options{})

			want := "[Container]\nImage=docker.io/library/nginx:1.27\n" + tc.want +
				"\n[Install]\nWantedBy=default.target\n"
			if got := snapshot(t, dir)["a.container"]; got != want {
				t.Errorf("a.container after fixing:\n%s\nwant:\n%s", got, want)
			}
			if again := fixOnce(t, dir, Options{}); len(again.Changes) != 0 {
				t.Errorf("a second fix changed %d files", len(again.Changes))
			}
			podmantest.AssertAccepts(t, generator, dir)
		})
	}
}

// TestFixRefusesToOverwriteANetworkOutsideTheProject guards issue #11: fixing
// a subset of a directory's units once replaced a hand-written shared.network
// with the template and reported it as created.
func TestFixRefusesToOverwriteANetworkOutsideTheProject(t *testing.T) {
	dir, project := writeUnits(t, map[string]string{
		"a.container": "[Container]\nImage=nginx\n[Install]\nWantedBy=default.target\n",
		"b.container": "[Container]\nImage=postgres\n[Install]\nWantedBy=default.target\n",
	})
	existing := filepath.Join(dir, "shared.network")
	handWritten := "[Network]\nSubnet=10.89.0.0/24\n"
	if err := os.WriteFile(existing, []byte(handWritten), 0o644); err != nil {
		t.Fatalf("writing: %v", err)
	}

	engine := &rules.Engine{Host: hostctx.Static{SELinuxMode: hostctx.SELinuxEnforcing}}
	_, err := Apply(project, engine.Run(project), Options{})

	want := existing + " already exists but is not among the units being fixed; " +
		"include it in the paths given to quaddoc, or move it aside, and re-run"
	if err == nil || err.Error() != want {
		t.Errorf("Apply error = %v, want %q", err, want)
	}
	if got := snapshot(t, dir)["shared.network"]; got != handWritten {
		t.Errorf("shared.network was changed:\n%s", got)
	}
}

// TestWriteNeverTruncatesAFileItMeantToCreate covers the window between Apply
// checking the disk and Write running.
func TestWriteNeverTruncatesAFileItMeantToCreate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shared.network")
	if err := os.WriteFile(path, []byte("[Network]\n"), 0o644); err != nil {
		t.Fatalf("writing: %v", err)
	}

	err := Write(&Result{Changes: []Change{{Path: path, After: "template\n", Created: true}}})
	if err == nil {
		t.Error("Write replaced a file it was only meant to create")
	}
	if got, _ := os.ReadFile(path); string(got) != "[Network]\n" {
		t.Errorf("the existing file was changed to %q", got)
	}
}

// TestFixQD022IgnoresACommentedKey guards issue #11: a commented-out WantedBy=
// was counted as a key, so the fix declined and the finding vanished.
func TestFixQD022IgnoresACommentedKey(t *testing.T) {
	dir, _ := writeUnits(t, map[string]string{
		"a.container": "[Container]\nImage=docker.io/library/alpine:3.20\n\n" +
			"[Install]\n# WantedBy=default.target\n",
	})
	result := fixOnce(t, dir, Options{})

	want := "[Container]\nImage=docker.io/library/alpine:3.20\n\n" +
		"[Install]\nWantedBy=default.target\n# WantedBy=default.target\n"
	if got := snapshot(t, dir)["a.container"]; got != want {
		t.Errorf("a.container after fixing:\n%s\nwant:\n%s", got, want)
	}
	if len(result.Unfixed) != 0 {
		t.Errorf("unfixed = %+v, want none", result.Unfixed)
	}
}

// TestADeclinedFixIsReportedAsUnfixed guards issue #11: a fixer that declined
// used to drop its finding, so the user saw "Nothing to fix." for a unit that
// lint still flags. A continued Volume= is declined: the old fix labelled the
// first physical line and wrote `Volume=\:Z`.
func TestADeclinedFixIsReportedAsUnfixed(t *testing.T) {
	original := "[Container]\nImage=docker.io/library/nginx:1.27\nVolume=\\\n  /srv/site:/data\n" +
		"[Install]\nWantedBy=default.target\n"
	dir, _ := writeUnits(t, map[string]string{"web.container": original})
	result := fixOnce(t, dir, Options{})

	if got := snapshot(t, dir)["web.container"]; got != original {
		t.Errorf("a declined fix changed the file:\n%s", got)
	}
	var ids []string
	for _, f := range result.Unfixed {
		ids = append(ids, f.RuleID)
	}
	if strings.Join(ids, ",") != "QD001" {
		t.Errorf("unfixed rules = %v, want [QD001]", ids)
	}
}

// TestFixQD001WritesTheMountSpelling covers issue #22: a Mount= bind mount is
// labelled with relabel=, which podman-run(1) --mount documents and which
// Podman 5.8.4 turns into the same :Z or :z a Volume= would carry. The
// generator passes the value through to --mount unchanged.
func TestFixQD001WritesTheMountSpelling(t *testing.T) {
	generator := podmantest.Generator(t)

	dir, _ := writeUnits(t, map[string]string{
		"web.container": "[Container]\nImage=docker.io/library/nginx:1.27\n" +
			"Mount=type=bind,source=/srv/web,destination=/data\n[Install]\nWantedBy=default.target\n",
		"a.container": "[Container]\nImage=docker.io/library/nginx:1.27\nNetwork=host\n" +
			"Mount=type=bind,src=/srv/s,dst=/data,ro\n[Install]\nWantedBy=default.target\n",
		"b.container": "[Container]\nImage=docker.io/library/nginx:1.27\nNetwork=host\n" +
			"Volume=/srv/s:/data\n[Install]\nWantedBy=default.target\n",
	})
	fixOnce(t, dir, Options{})
	once := snapshot(t, dir)

	want := map[string]string{
		"web.container": "Mount=type=bind,source=/srv/web,destination=/data,relabel=private\n",
		"a.container":   "Mount=type=bind,src=/srv/s,dst=/data,ro,relabel=shared\n",
		"b.container":   "Volume=/srv/s:/data:z\n",
	}
	for name, line := range want {
		if !strings.Contains(once[name], "\n"+line) {
			t.Errorf("%s after fixing:\n%s\nwant it to contain %q", name, once[name], line)
		}
	}

	fixOnce(t, dir, Options{})
	for name, content := range snapshot(t, dir) {
		if content != once[name] {
			t.Errorf("%s changed on the second run:\n%s", name, content)
		}
	}

	podmantest.AssertAccepts(t, generator, dir)
	cmd := exec.Command(generator, "-dryrun", "-user")
	cmd.Env = append(os.Environ(), "QUADLET_UNIT_DIRS="+dir)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("generator: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "--mount type=bind,source=/srv/web,destination=/data,relabel=private ") {
		t.Errorf("the generator did not pass relabel=private through to --mount:\n%s", out)
	}
}

func TestFixQD001GuardsMountEntries(t *testing.T) {
	tests := []struct {
		name   string
		line   string
		option string
		want   string // empty: declined
	}{
		{
			name: "an unlabelled bind is labelled", option: "Z",
			line: "Mount=type=bind,source=/s,destination=/d",
			want: "Mount=type=bind,source=/s,destination=/d,relabel=private",
		},
		{
			name: "a shared label is spelled relabel=shared", option: "z",
			line: "Mount=type=bind,source=/s,destination=/d,U=true",
			want: "Mount=type=bind,source=/s,destination=/d,U=true,relabel=shared",
		},
		{name: "relabel= already present", option: "Z", line: "Mount=type=bind,source=/s,destination=/d,relabel=shared"},
		{name: "a bare Z already present", option: "z", line: "Mount=type=bind,source=/s,destination=/d,Z"},
		{name: "an invalid relabel podman rejects", option: "Z", line: "Mount=type=bind,source=/s,destination=/d,relabel=Private"},
		{name: "a volume mount", option: "Z", line: "Mount=type=volume,source=v,destination=/d"},
		{name: "a lowercase mount key", option: "Z", line: "mount=type=bind,source=/s,destination=/d"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lines := parseLines(t, "[Container]", tt.line)
			finding := rules.Finding{RuleID: "QD001", Line: 2, Fix: map[string]string{"option": tt.option}}

			got, changed := fixQD001(lines, finding)
			want := tt.want
			if want == "" {
				want = tt.line
			}
			if changed != (tt.want != "") || got[1].Raw[0] != want {
				t.Errorf("changed = %v, line = %q; want %q", changed, got[1].Raw[0], want)
			}
		})
	}
}

// TestFixMatchesSectionNamesExactly: Quadlet and systemd match section and key
// names exactly, so a lowercase [install], [container], network= or volume= is
// not what the rule meant and must not satisfy or receive a fix.
func TestFixMatchesSectionNamesExactly(t *testing.T) {
	got, changed := fixQD022(parseLines(t, "[Container]", "Image=nginx", "", "[install]", "WantedBy=default.target"))
	if !changed || countOccurrences(got, "[Install]") != 1 || countOccurrences(got, "WantedBy=default.target") != 2 {
		t.Errorf("a lowercase [install] should not stop [Install] being added: %v", got)
	}

	if got, changed := fixQD030(parseLines(t, "[container]", "Image=nginx"), "shared", ""); changed {
		t.Errorf("Network= was written into a lowercase [container]: %v", got)
	}

	got, changed = fixQD030(parseLines(t, "[Container]", "Image=nginx", "network=shared.network"), "shared", "")
	if !changed || countOccurrences(got, "Network=shared.network") != 1 {
		t.Errorf("a lowercase network= key should not count as wired in: %v", got)
	}

	finding := rules.Finding{RuleID: "QD001", Line: 2, Fix: map[string]string{"option": "Z"}}
	if got, changed := fixQD001(parseLines(t, "[Container]", "volume=/srv:/data"), finding); changed {
		t.Errorf("a lowercase volume= key was labelled: %q", got[1].Raw)
	}
}

// parseLines parses physical lines into the logical lines the fixers take.
func parseLines(t *testing.T, physical ...string) []quadlet.Line {
	t.Helper()
	f, err := quadlet.Parse("test.container", strings.NewReader(strings.Join(physical, "\n")))
	if err != nil {
		t.Fatalf("parsing: %v", err)
	}
	return f.Lines
}

func countOccurrences(lines []quadlet.Line, want string) int {
	n := 0
	for _, l := range lines {
		for _, raw := range l.Raw {
			if strings.TrimSpace(raw) == want {
				n++
			}
		}
	}
	return n
}
