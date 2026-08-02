package main

// The subcommands here were added after the first test pass and were exercised
// only by hand. Anything only ever checked by hand regresses silently, so each
// one gets an end-to-end test through the real binary.

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MatrixMagician/quaddoc/internal/rules"
)

const fixtureCompose = `
services:
  web:
    image: docker.io/library/nginx:1.27
    ports: ["8080:80"]
    volumes: ["./site:/usr/share/nginx/html"]
    depends_on:
      db: { condition: service_healthy }
    restart: unless-stopped
  db:
    image: docker.io/library/postgres:16
    volumes: ["pgdata:/var/lib/postgresql/data"]
    environment:
      POSTGRES_PASSWORD: hunter2
    healthcheck:
      test: ["CMD", "pg_isready"]
      start_period: 30s
volumes:
  pgdata:
`

// writeCompose puts a compose file in a fresh directory.
func writeCompose(t *testing.T, body string) (dir, path string) {
	t.Helper()
	dir = t.TempDir()
	path = filepath.Join(dir, "compose.yaml")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("writing compose: %v", err)
	}
	return dir, path
}

func TestConvertWritesUnits(t *testing.T) {
	bin := buildCLI(t)
	dir, compose := writeCompose(t, fixtureCompose)
	out := filepath.Join(dir, "units")

	_, stderr, code := run(t, bin, "convert", compose, "--out", out)
	// Translation notes make the exit code non-zero; what matters here is
	// that the units were written.
	if code > 1 {
		t.Fatalf("exit = %d\nstderr: %s", code, stderr)
	}

	for _, name := range []string{"web.container", "db.container", "pgdata.volume"} {
		if _, err := os.Stat(filepath.Join(out, name)); err != nil {
			t.Errorf("%s was not written: %v", name, err)
		}
	}
}

// TestConvertAcceptsFlagsAfterThePath is the regression test for the flag
// ordering bug found during development: Go's flag package stops at the first
// non-flag argument, so `convert file.yaml --out dir` silently ignored --out
// and wrote to the default directory instead.
func TestConvertAcceptsFlagsAfterThePath(t *testing.T) {
	bin := buildCLI(t)
	dir, compose := writeCompose(t, fixtureCompose)

	for _, args := range [][]string{
		{"convert", compose, "--out", filepath.Join(dir, "after")},
		{"convert", "--out", filepath.Join(dir, "before"), compose},
		{"convert", compose, "--out=" + filepath.Join(dir, "equals")},
	} {
		t.Run(strings.Join(args[1:], " "), func(t *testing.T) {
			if _, stderr, code := run(t, bin, args...); code > 1 {
				t.Fatalf("exit = %d\nstderr: %s", code, stderr)
			}
		})
	}

	for _, name := range []string{"after", "before", "equals"} {
		if _, err := os.Stat(filepath.Join(dir, name, "web.container")); err != nil {
			t.Errorf("--out was ignored for the %q form: %v", name, err)
		}
	}
}

func TestConvertDryRunWritesNothing(t *testing.T) {
	bin := buildCLI(t)
	dir, compose := writeCompose(t, fixtureCompose)
	out := filepath.Join(dir, "units")

	stdout, _, _ := run(t, bin, "convert", compose, "--dry-run", "--out", out)

	// The units go to stdout, named, so the output is reviewable and pipeable.
	for _, want := range []string{"web.container", "db.container", "pgdata.volume", "[Container]"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("--dry-run output omits %q:\n%s", want, stdout)
		}
	}

	// Nothing at all should reach the disk. Checking only that the directory
	// is absent is too weak: a previous run, or a differently named output
	// directory, would slip through. Compare the whole tree before and after.
	if _, err := os.Stat(out); err == nil {
		t.Fatal("--dry-run created the output directory")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading %s: %v", dir, err)
	}
	if len(entries) != 1 || entries[0].Name() != "compose.yaml" {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("--dry-run left files behind: %v", names)
	}
}

func TestConvertPodMode(t *testing.T) {
	bin := buildCLI(t)
	dir, compose := writeCompose(t, fixtureCompose)
	out := filepath.Join(dir, "units")

	if _, stderr, code := run(t, bin, "convert", compose, "--pod", "--out", out); code > 1 {
		t.Fatalf("exit = %d\nstderr: %s", code, stderr)
	}

	entries, err := os.ReadDir(out)
	if err != nil {
		t.Fatalf("reading output: %v", err)
	}
	var sawPod bool
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".pod") {
			sawPod = true
		}
	}
	if !sawPod {
		t.Error("--pod did not emit a .pod unit")
	}
}

func TestConvertRejectsAMissingFile(t *testing.T) {
	bin := buildCLI(t)

	_, stderr, code := run(t, bin, "convert", filepath.Join(t.TempDir(), "nope.yaml"))
	if code != 2 {
		t.Errorf("exit = %d, want 2", code)
	}
	if stderr == "" {
		t.Error("a missing compose file should be explained")
	}
}

func TestFixPreviewsByDefaultAndWritesOnDemand(t *testing.T) {
	// Previewing by default is the safety property: a tool that edits files
	// because you asked it a question is not one people leave installed.
	bin := buildCLI(t)
	dir := writeUnits(t, map[string]string{
		"web.container": "[Container]\nImage=docker.io/library/nginx:1.27\n",
	})
	before, err := os.ReadFile(filepath.Join(dir, "web.container"))
	if err != nil {
		t.Fatalf("reading: %v", err)
	}

	stdout, _, code := run(t, bin, "fix", dir)
	if code != 0 {
		t.Fatalf("preview exit = %d", code)
	}
	if !strings.Contains(stdout, "+[Install]") {
		t.Errorf("preview does not show the change:\n%s", stdout)
	}

	after, _ := os.ReadFile(filepath.Join(dir, "web.container"))
	if string(after) != string(before) {
		t.Error("the preview modified the file")
	}

	if _, _, code := run(t, bin, "fix", dir, "--write"); code != 0 {
		t.Fatalf("write exit = %d", code)
	}
	written, _ := os.ReadFile(filepath.Join(dir, "web.container"))
	if !strings.Contains(string(written), "[Install]") {
		t.Errorf("--write did not apply the change:\n%s", written)
	}
}

func TestFixEndToEndLeavesTheProjectClean(t *testing.T) {
	// The full loop a user runs: lint fails, fix, lint passes.
	bin := buildCLI(t)
	dir := writeUnits(t, map[string]string{
		"a.container": "[Container]\nImage=docker.io/library/nginx:1.27\nVolume=/srv/s:/data\n",
		"b.container": "[Container]\nImage=docker.io/library/postgres:16\nVolume=/srv/s:/backup\n",
	})

	if _, _, code := run(t, bin, "lint", dir); code != 2 {
		t.Fatalf("expected errors before fixing, got exit %d", code)
	}
	if _, stderr, code := run(t, bin, "fix", dir, "--write"); code != 0 {
		t.Fatalf("fix exit = %d\nstderr: %s", code, stderr)
	}

	stdout, _, code := run(t, bin, "lint", dir)
	if code == 2 {
		t.Errorf("errors remain after fixing:\n%s", stdout)
	}
}

func TestFixRuleFilter(t *testing.T) {
	bin := buildCLI(t)
	dir := writeUnits(t, map[string]string{
		"web.container": "[Container]\nImage=docker.io/library/nginx:1.27\nVolume=/srv/s:/data\n",
	})

	stdout, stderr, code := run(t, bin, "fix", dir, "--rule", "QD022", "--write")
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}

	after, _ := os.ReadFile(filepath.Join(dir, "web.container"))
	if !strings.Contains(string(after), "[Install]") {
		t.Errorf("the requested rule was not applied:\n%s", after)
	}
	if strings.Contains(string(after), ":Z") {
		t.Errorf("an unrequested rule was applied:\n%s", after)
	}

	// The filter must also be reflected in what the run reports: the applied
	// rule named, and the excluded one listed as still needing attention.
	if !strings.Contains(stdout, "QD022") {
		t.Errorf("the applied rule is not reported:\n%s", stdout)
	}
	if !strings.Contains(stderr, "QD001") {
		t.Errorf("the excluded rule should be reported as unfixed:\n%s", stderr)
	}

	// And a second run with no filter should then apply the rest.
	if _, _, code := run(t, bin, "fix", dir, "--write"); code != 0 {
		t.Fatalf("second fix exit = %d", code)
	}
	after, _ = os.ReadFile(filepath.Join(dir, "web.container"))
	if !strings.Contains(string(after), ":Z") {
		t.Errorf("the unfiltered run did not apply the remaining rule:\n%s", after)
	}
}

func TestCaptureContextAndReplay(t *testing.T) {
	// Capture on the broken machine, lint anywhere. The two must agree, or
	// every context-dependent finding becomes untrustworthy.
	bin := buildCLI(t)
	dir := t.TempDir()
	ctx := filepath.Join(dir, "ctx")

	if _, stderr, code := run(t, bin, "capture-context", "--out", ctx); code != 0 {
		t.Fatalf("capture exit = %d\nstderr: %s", code, stderr)
	}

	// The capture must land in the directory the user named, and must contain
	// the facts the rules consult. Checking only that the directory exists
	// would pass even if the contents went somewhere else entirely.
	info, err := os.Stat(ctx)
	if err != nil || !info.IsDir() {
		t.Fatalf("capture did not write to the requested directory: %v", err)
	}

	var files int
	if err := filepath.Walk(ctx, func(_ string, fi os.FileInfo, err error) error {
		if err == nil && !fi.IsDir() {
			files++
		}
		return nil
	}); err != nil {
		t.Fatalf("walking the capture: %v", err)
	}
	if files == 0 {
		t.Fatal("the captured directory is empty")
	}
	if _, err := os.Stat(filepath.Join(ctx, "quaddoc-rootless")); err != nil {
		t.Errorf("the capture does not record the rootless status: %v", err)
	}
	if _, err := os.Stat(filepath.Join(ctx, "proc/self/mountinfo")); err != nil {
		t.Errorf("the capture does not record the mount table: %v", err)
	}

	units := writeUnits(t, map[string]string{
		"web.container": "[Container]\nImage=docker.io/library/nginx:1.27\n" +
			"Volume=/srv/site:/data\n[Install]\nWantedBy=default.target\n",
	})

	live, _, _ := run(t, bin, "lint", "--host-context=live", "--json", units)
	replay, _, _ := run(t, bin, "lint", "--host-context="+ctx, "--json", units)

	if live != replay {
		t.Errorf("replay does not match live:\n--- live ---\n%s\n--- replay ---\n%s", live, replay)
	}
}

func TestHostContextChangesConfidence(t *testing.T) {
	// Without host context a finding is a possibility; with it, a fact. The
	// wording must differ, or the tool asserts things it has not checked.
	bin := buildCLI(t)
	units := writeUnits(t, map[string]string{
		"web.container": "[Container]\nImage=docker.io/library/nginx:1.27\n" +
			"Volume=/srv/site:/data\n[Install]\nWantedBy=default.target\n",
	})

	without, _, _ := run(t, bin, "lint", "--json", units)
	with, _, _ := run(t, bin, "lint", "--host-context=live", "--json", units)

	if !strings.Contains(without, `"confidence": "possible"`) {
		t.Errorf("without host context, findings should be possible:\n%s", without)
	}
	if !strings.Contains(with, `"confidence": "confirmed"`) {
		t.Errorf("with host context, findings should be confirmed:\n%s", with)
	}
}

func TestLintRejectsABadHostContextPath(t *testing.T) {
	bin := buildCLI(t)
	units := writeUnits(t, map[string]string{"web.container": "[Container]\nImage=nginx\n"})

	_, stderr, code := run(t, bin, "lint",
		"--host-context="+filepath.Join(t.TempDir(), "nope"), units)
	if code != 2 {
		t.Errorf("exit = %d, want 2 for a missing capture directory", code)
	}
	if stderr == "" {
		t.Error("a missing capture directory should be explained")
	}
}

func TestDoctorReportsTheEnvironment(t *testing.T) {
	bin := buildCLI(t)

	stdout, _, code := run(t, bin, "doctor")
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}

	// Assert the reported values, not merely the labels: a doctor that prints
	// "SELinux:" with nothing after it passes a label-only check while
	// telling the user nothing.
	for _, want := range []string{
		"SELinux: ", "Podman mode: ", "Subordinate UIDs: ",
		"Unprivileged ports: ", "Installed Quadlet units: ", "Rules registered: ",
	} {
		i := strings.Index(stdout, want)
		if i < 0 {
			t.Errorf("doctor omits %q:\n%s", want, stdout)
			continue
		}
		rest := stdout[i+len(want):]
		if line, _, _ := strings.Cut(rest, "\n"); strings.TrimSpace(line) == "" {
			t.Errorf("doctor reports %q with no value:\n%s", want, stdout)
		}
	}

	// The rule count must be the real one, so that a doctor run confirms the
	// binary has the rules the user expects.
	if !strings.Contains(stdout, fmt.Sprintf("Rules registered: %d", len(rules.All()))) {
		t.Errorf("doctor does not report the real rule count (%d):\n%s", len(rules.All()), stdout)
	}

	// Replaying a captured context must work through doctor too.
	ctx := filepath.Join(t.TempDir(), "ctx")
	if _, _, code := run(t, bin, "capture-context", "--out", ctx); code != 0 {
		t.Fatalf("capture exit = %d", code)
	}
	replayed, _, code := run(t, bin, "doctor", "--host-context="+ctx)
	if code != 0 {
		t.Fatalf("doctor replay exit = %d", code)
	}
	if !strings.Contains(replayed, "SELinux: ") {
		t.Errorf("doctor against a captured context reports nothing:\n%s", replayed)
	}
}

func TestSARIFOutputFromTheCLI(t *testing.T) {
	bin := buildCLI(t)
	units := writeUnits(t, map[string]string{
		"web.container": "[Container]\nImage=docker.io/library/nginx:1.27\n",
	})

	stdout, _, _ := run(t, bin, "lint", "--sarif", units)

	var log struct {
		Version string `json:"version"`
		Runs    []struct {
			Results []struct {
				RuleID string `json:"ruleId"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal([]byte(stdout), &log); err != nil {
		t.Fatalf("SARIF output is not valid JSON: %v\n%s", err, stdout)
	}
	if log.Version != "2.1.0" {
		t.Errorf("SARIF version = %q, want 2.1.0", log.Version)
	}
	if len(log.Runs) != 1 || len(log.Runs[0].Results) == 0 {
		t.Errorf("expected results in the SARIF output:\n%s", stdout)
	}
}

func TestConfigFileIsHonoured(t *testing.T) {
	bin := buildCLI(t)
	dir := writeUnits(t, map[string]string{
		"web.container": "[Container]\nImage=docker.io/library/nginx:1.27\n",
	})

	// QD022 is an error, so the project fails.
	if _, _, code := run(t, bin, "lint", dir); code != 2 {
		t.Fatalf("expected exit 2 before configuring, got %d", code)
	}

	if err := os.WriteFile(filepath.Join(dir, ".quaddoc.toml"),
		[]byte("[rules]\nQD022 = \"note\"\n"), 0o644); err != nil {
		t.Fatalf("writing config: %v", err)
	}

	if _, _, code := run(t, bin, "lint", dir); code != 0 {
		t.Errorf("the configuration was not honoured; exit = %d", code)
	}
}

func TestConfigFileRejectsAnUnknownRule(t *testing.T) {
	// A typo'd rule ID would otherwise sit in the file doing nothing.
	bin := buildCLI(t)
	dir := writeUnits(t, map[string]string{"web.container": "[Container]\nImage=nginx\n"})

	if err := os.WriteFile(filepath.Join(dir, ".quaddoc.toml"),
		[]byte("[rules]\nQD999 = \"off\"\n"), 0o644); err != nil {
		t.Fatalf("writing config: %v", err)
	}

	_, stderr, code := run(t, bin, "lint", dir)
	if code != 2 {
		t.Errorf("exit = %d, want 2 for an invalid configuration", code)
	}
	if !strings.Contains(stderr, "QD999") {
		t.Errorf("stderr should name the unknown rule: %s", stderr)
	}
}

func TestInlineSuppressionNeedsAReason(t *testing.T) {
	bin := buildCLI(t)

	withReason := writeUnits(t, map[string]string{
		"web.container": "# quaddoc: disable=QD022 started by a timer, not at boot\n" +
			"[Container]\nImage=docker.io/library/nginx:1.27\n",
	})
	if _, _, code := run(t, bin, "lint", withReason); code != 0 {
		t.Errorf("a reasoned suppression should silence the rule; exit = %d", code)
	}

	withoutReason := writeUnits(t, map[string]string{
		"web.container": "# quaddoc: disable=QD022\n" +
			"[Container]\nImage=docker.io/library/nginx:1.27\n",
	})
	stdout, _, code := run(t, bin, "lint", withoutReason)
	if code == 0 {
		t.Error("an unreasoned suppression should not silence anything")
	}
	if !strings.Contains(stdout, "QD000") {
		t.Errorf("an unreasoned suppression should be reported:\n%s", stdout)
	}
}

func TestRulesMarkdownIsGenerated(t *testing.T) {
	bin := buildCLI(t)

	stdout, _, code := run(t, bin, "rules", "--markdown")
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	if !strings.HasPrefix(stdout, "# QuadDoc rule reference") {
		t.Error("unexpected markdown output")
	}
	if !strings.Contains(stdout, "## QD001") {
		t.Error("the markdown reference omits QD001")
	}
}

// TestConvertedThenFixedUnitsPassTheRealGenerator runs the whole user journey
// against Podman's own generator, which is the only authority on whether a
// unit is valid.
func TestConvertedThenFixedUnitsPassTheRealGenerator(t *testing.T) {
	generator := findGenerator()
	if generator == "" {
		t.Skip("Quadlet generator not installed")
	}

	bin := buildCLI(t)
	dir, compose := writeCompose(t, fixtureCompose)
	out := filepath.Join(dir, "units")

	if _, stderr, code := run(t, bin, "convert", compose, "--out", out); code > 1 {
		t.Fatalf("convert exit = %d\nstderr: %s", code, stderr)
	}
	assertGeneratorAccepts(t, generator, out)

	if _, stderr, code := run(t, bin, "fix", out, "--write"); code != 0 {
		t.Fatalf("fix exit = %d\nstderr: %s", code, stderr)
	}
	assertGeneratorAccepts(t, generator, out)
}

func assertGeneratorAccepts(t *testing.T, generator, dir string) {
	t.Helper()

	cmd := exec.Command(generator, "-dryrun", "-user")
	cmd.Env = append(os.Environ(), "QUADLET_UNIT_DIRS="+dir)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("the generator rejected the units in %s: %v\n%s", dir, err, out)
	}
}

func findGenerator() string {
	for _, path := range []string{
		"/usr/libexec/podman/quadlet",
		"/usr/lib/podman/quadlet",
		"/usr/local/libexec/podman/quadlet",
	} {
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			return path
		}
	}
	return ""
}
