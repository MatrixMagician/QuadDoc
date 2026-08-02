package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// builtCLI caches the compiled binary for the whole test run.
//
// These tests deliberately exercise the real command-line surface rather than
// calling internals, which means compiling. Doing that per test cost 31 `go
// build` invocations and about 7 seconds, against 0.13s for every other
// package combined. Building once brings the suite back to something you can
// run on every save.
var builtCLI struct {
	once sync.Once
	path string
	err  error
}

// buildCLI compiles the binary once per test run and returns its path.
func buildCLI(t *testing.T) string {
	t.Helper()

	builtCLI.once.Do(func() {
		// Not t.TempDir(): that is removed when the first test finishes,
		// which would delete the binary the rest still need.
		dir, err := os.MkdirTemp("", "quaddoc-test-")
		if err != nil {
			builtCLI.err = err
			return
		}
		bin := filepath.Join(dir, "quaddoc")

		cmd := exec.Command("go", "build", "-o", bin, ".")
		if out, err := cmd.CombinedOutput(); err != nil {
			builtCLI.err = fmt.Errorf("building quaddoc: %w\n%s", err, out)
			return
		}
		builtCLI.path = bin
	})

	if builtCLI.err != nil {
		t.Fatalf("%v", builtCLI.err)
	}
	return builtCLI.path
}

// run executes the binary and returns stdout, stderr, and the exit code.
//
// The working directory is a throwaway one, so that a bug in flag handling
// cannot scribble into the repository. A mutation that made `--out` fall back
// to its default did exactly that before this was added.
func run(t *testing.T, bin string, args ...string) (string, string, int) {
	t.Helper()

	cmd := exec.Command(bin, args...)
	cmd.Dir = t.TempDir()
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	// Keep colour out of the assertions.
	cmd.Env = append(os.Environ(), "NO_COLOR=1")

	err := cmd.Run()
	code := 0
	if exit, ok := err.(*exec.ExitError); ok {
		code = exit.ExitCode()
	} else if err != nil {
		t.Fatalf("running quaddoc: %v", err)
	}
	return stdout.String(), stderr.String(), code
}

// writeUnits creates a directory of unit files.
func writeUnits(t *testing.T, units map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range units {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatalf("writing %s: %v", name, err)
		}
	}
	return dir
}

func TestLintExitCodes(t *testing.T) {
	bin := buildCLI(t)

	tests := []struct {
		name  string
		units map[string]string
		want  int
	}{
		{
			name: "a clean project exits 0",
			units: map[string]string{
				"web.container": "[Container]\nImage=docker.io/library/nginx:1.27\n" +
					"[Install]\nWantedBy=default.target\n",
			},
			want: 0,
		},
		{
			name: "a warning exits 1",
			units: map[string]string{
				"web.container": "[Container]\nImage=docker.io/library/nginx:1.27\n" +
					"[Install]\nWantedBy=default.target\nAlso=nope.service\n",
			},
			want: 1,
		},
		{
			name: "an error exits 2",
			units: map[string]string{
				"web.container": "[Container]\nImage=docker.io/library/nginx:1.27\n",
			},
			want: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := writeUnits(t, tt.units)
			_, stderr, code := run(t, bin, "lint", dir)
			if code != tt.want {
				t.Errorf("exit = %d, want %d\nstderr: %s", code, tt.want, stderr)
			}
		})
	}
}

func TestLintJSONIsParseable(t *testing.T) {
	bin := buildCLI(t)
	dir := writeUnits(t, map[string]string{
		"web.container": "[Container]\nImage=docker.io/library/nginx:1.27\n",
	})

	stdout, stderr, code := run(t, bin, "lint", "--json", dir)
	if code != 2 {
		t.Fatalf("exit = %d, want 2\nstderr: %s", code, stderr)
	}

	var report struct {
		Version  int `json:"version"`
		Findings []struct {
			Rule     string `json:"rule"`
			Severity string `json:"severity"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, stdout)
	}
	if report.Version == 0 {
		t.Error("report carries no schema version")
	}
	if len(report.Findings) == 0 {
		t.Fatal("expected findings")
	}
	if report.Findings[0].Rule != "QD022" {
		t.Errorf("first finding = %s, want QD022", report.Findings[0].Rule)
	}
}

func TestLintIgnoresNonUnitFiles(t *testing.T) {
	// Pointing quaddoc at a directory that also holds a README or a compose
	// file should be harmless.
	bin := buildCLI(t)
	dir := writeUnits(t, map[string]string{
		"web.container": "[Container]\nImage=nginx\n[Install]\nWantedBy=default.target\n",
		"README.md":     "# not a unit\n",
		"compose.yaml":  "services:\n  web:\n    image: nginx\n",
	})

	stdout, stderr, code := run(t, bin, "lint", dir)
	if code != 0 {
		t.Errorf("exit = %d, want 0\nstdout: %s\nstderr: %s", code, stdout, stderr)
	}
}

func TestLintDisableFlag(t *testing.T) {
	bin := buildCLI(t)
	dir := writeUnits(t, map[string]string{
		"web.container": "[Container]\nImage=docker.io/library/nginx:1.27\n",
	})

	_, _, code := run(t, bin, "lint", "--disable", "QD022", dir)
	if code != 0 {
		t.Errorf("exit = %d, want 0 once the only failing rule is disabled", code)
	}
}

func TestLintRejectsMissingPath(t *testing.T) {
	bin := buildCLI(t)

	_, stderr, code := run(t, bin, "lint", filepath.Join(t.TempDir(), "nope"))
	if code != 2 {
		t.Errorf("exit = %d, want 2 for a missing path", code)
	}
	if stderr == "" {
		t.Error("a missing path should be explained on stderr")
	}
}

func TestLintWithNoPaths(t *testing.T) {
	bin := buildCLI(t)

	_, stderr, code := run(t, bin, "lint")
	if code != 2 {
		t.Errorf("exit = %d, want 2", code)
	}
	if !strings.Contains(stderr, "no paths") {
		t.Errorf("stderr should explain that no paths were given, got: %s", stderr)
	}
}

func TestRulesReference(t *testing.T) {
	bin := buildCLI(t)

	stdout, _, code := run(t, bin, "rules")
	if code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}
	if !strings.Contains(stdout, "QD022") {
		t.Errorf("rules listing omits QD022:\n%s", stdout)
	}
}

func TestRulesSingleRuleShowsCitation(t *testing.T) {
	// The citation is the project's guard against encoding folklore, so it
	// must be visible to a user asking about a rule.
	bin := buildCLI(t)

	stdout, _, code := run(t, bin, "rules", "QD022")
	if code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}
	if !strings.Contains(stdout, "Source:") {
		t.Errorf("rule detail omits its citation:\n%s", stdout)
	}
	if !strings.Contains(stdout, "podman-systemd.unit(5)") {
		t.Errorf("QD022's citation should name the manual page:\n%s", stdout)
	}
}

func TestUnknownRuleIsAnError(t *testing.T) {
	bin := buildCLI(t)

	_, stderr, code := run(t, bin, "rules", "QD999")
	if code != 2 {
		t.Errorf("exit = %d, want 2", code)
	}
	if !strings.Contains(stderr, "QD999") {
		t.Errorf("stderr should name the unknown rule, got: %s", stderr)
	}
}

func TestUnknownCommand(t *testing.T) {
	bin := buildCLI(t)

	_, stderr, code := run(t, bin, "frobnicate")
	if code != 2 {
		t.Errorf("exit = %d, want 2", code)
	}
	if !strings.Contains(stderr, "frobnicate") {
		t.Errorf("stderr should name the unknown command, got: %s", stderr)
	}
}

func TestVersion(t *testing.T) {
	bin := buildCLI(t)

	stdout, _, code := run(t, bin, "version")
	if code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}
	if !strings.HasPrefix(stdout, "quaddoc ") {
		t.Errorf("version output = %q", stdout)
	}
}

func TestLintSingleFileByName(t *testing.T) {
	// A file named explicitly is linted whatever its extension: the user
	// asked for it by name.
	bin := buildCLI(t)
	dir := writeUnits(t, map[string]string{
		"web.container": "[Container]\nImage=docker.io/library/nginx:1.27\n",
	})

	_, _, code := run(t, bin, "lint", filepath.Join(dir, "web.container"))
	if code != 2 {
		t.Errorf("exit = %d, want 2", code)
	}
}
