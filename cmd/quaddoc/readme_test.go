package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite golden files")

// TestReadmeWalkthrough runs the README's compose file through convert, lint,
// and fix, and checks the result two ways. The full transcript is compared
// against a golden file, so any change to the output fails here first. The
// lines the README quotes verbatim (unit count, finding positions, totals, fix
// summary) must also appear in the README itself. #49 refreshed the walkthrough
// from a different compose file than the one it shows, and nothing noticed.
func TestReadmeWalkthrough(t *testing.T) {
	readme, err := os.ReadFile(filepath.Join("..", "..", "README.md"))
	if err != nil {
		t.Fatalf("reading README: %v", err)
	}
	compose := regexp.MustCompile("(?s)```yaml\n(services:.*?)```").FindSubmatch(readme)
	if compose == nil {
		t.Fatal("README has no ```yaml block starting with services:")
	}

	bin := buildCLI(t)
	dir := fixedLengthDir(t, 64)
	if err := os.WriteFile(filepath.Join(dir, "compose.yaml"), compose[1], 0o644); err != nil {
		t.Fatalf("writing compose: %v", err)
	}

	var transcript strings.Builder
	for _, args := range [][]string{
		{"convert", "compose.yaml", "--out", "units/"},
		{"lint", "units/"},
		{"fix", "units/", "--write"},
	} {
		stdout, stderr, code := runIn(t, dir, bin, args...)
		fmt.Fprintf(&transcript, "$ quaddoc %s\n# exit %d\n# stdout\n%s# stderr\n%s\n",
			strings.Join(args, " "), code, stdout, stderr)
	}
	// Absolute paths vary per run. The README shortens them the same way.
	got := strings.ReplaceAll(transcript.String(), dir, "...")

	golden(t, "readme-walkthrough.golden", []byte(got))

	quoted := regexp.MustCompile(`(?m)^(?:Wrote \d+ units to .*|Found .*|updated .*|\d+ finding\(s\) have no mechanical fix.*|  QD\d{3} .* \(\d+\))$` +
		`|(?:error|warning|note):\d+ QD\d{3}`)
	for _, line := range quoted.FindAllString(got, -1) {
		if !strings.Contains(string(readme), line) {
			t.Errorf("README does not show %q; update its walkthrough from testdata/readme-walkthrough.golden", line)
		}
	}
}

// fixedLengthDir returns an empty directory named demo whose absolute path is
// exactly n bytes long. convert's comments wrap absolute bind-mount paths, so
// the line numbers lint reports depend on the path's length, and t.TempDir's
// length varies from run to run.
func fixedLengthDir(t *testing.T, n int) string {
	t.Helper()
	base := t.TempDir()
	pad := n - len(base) - len("//demo")
	if pad < 1 {
		t.Fatalf("temporary directory %s is too long for a %d-byte path; set a shorter TMPDIR", base, n)
	}
	dir := filepath.Join(base, strings.Repeat("p", pad), "demo")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("creating %s: %v", dir, err)
	}
	return dir
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
		t.Fatalf("reading golden %s (run `go test ./cmd/quaddoc -update` to create it): %v", path, err)
	}
	if string(want) != string(got) {
		t.Errorf("%s is out of date; run `go test ./cmd/quaddoc -update`, then update the README walkthrough to match\ngot:\n%s", path, got)
	}
}
