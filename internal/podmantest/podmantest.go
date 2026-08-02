// Package podmantest locates Podman's Quadlet generator for acceptance tests.
//
// The generator is the only authority on whether a unit file is valid, so
// several packages check their output against it. Go cannot share code between
// package-local test files, which is why this is an ordinary package rather
// than a helper copied into each one; it was copied three times before this
// existed, and the copies had already begun to drift.
package podmantest

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
)

// MinimumPodman is the oldest release this project supports, per ADR-0002.
//
// Keys such as Pod= do not exist before it, so running the acceptance tests
// against an older generator reports failures that are really the runner's age.
// Ubuntu's packaged Podman is old enough to fail exactly that way.
var MinimumPodman = Version{Major: 5, Minor: 0}

// Version is a Podman release.
type Version struct {
	Major int
	Minor int
}

// Before reports whether v precedes other.
func (v Version) Before(other Version) bool {
	if v.Major != other.Major {
		return v.Major < other.Major
	}
	return v.Minor < other.Minor
}

// String renders the version as `major.minor`.
func (v Version) String() string {
	return strconv.Itoa(v.Major) + "." + strconv.Itoa(v.Minor)
}

// generatorPaths are where distributions install the Quadlet generator. It is
// deliberately not on PATH, being a systemd generator rather than a command.
var generatorPaths = []string{
	"/usr/libexec/podman/quadlet",
	"/usr/lib/podman/quadlet",
	"/usr/local/libexec/podman/quadlet",
}

// Generator returns the path to the Quadlet generator, skipping the test when
// it is absent or older than the supported minimum.
//
// Skipping rather than failing is deliberate: a contributor without Podman
// should still be able to run the suite, and a runner with an old Podman should
// report its age rather than a fabricated defect in the units.
func Generator(t *testing.T) string {
	t.Helper()

	path := GeneratorPath()
	if path == "" {
		t.Skip("Quadlet generator not installed; skipping the real-generator check")
	}

	version, ok := PodmanVersion()
	if !ok {
		t.Skipf("cannot determine the Podman version for %s; skipping", path)
	}
	if version.Before(MinimumPodman) {
		t.Skipf("Podman %s is older than the supported minimum of %s (ADR-0002); skipping",
			version, MinimumPodman)
	}
	return path
}

// GeneratorPath returns the generator's location, or empty if it is not
// installed. Callers wanting a skip should use Generator.
func GeneratorPath() string {
	for _, candidate := range generatorPaths {
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate
		}
	}
	return ""
}

// PodmanVersion reports the installed Podman version.
func PodmanVersion() (Version, bool) {
	out, err := exec.Command("podman", "--version").Output()
	if err != nil {
		return Version{}, false
	}

	// `podman version 5.8.4`
	fields := strings.Fields(string(out))
	if len(fields) < 3 {
		return Version{}, false
	}

	parts := strings.SplitN(strings.TrimSpace(fields[2]), ".", 3)
	if len(parts) < 2 {
		return Version{}, false
	}
	major, err1 := strconv.Atoi(parts[0])
	minor, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil {
		return Version{}, false
	}
	return Version{Major: major, Minor: minor}, true
}

// AssertAccepts runs the generator over a directory of units and fails the test
// if it rejects them or complains.
//
// This is the acceptance check for conversion and for the fix engine: golden
// files prove the output has not changed, whereas this proves Podman actually
// accepts it.
func AssertAccepts(t *testing.T, generator, dir string) {
	t.Helper()

	cmd := exec.Command(generator, "-dryrun", "-user")
	cmd.Env = append(os.Environ(), "QUADLET_UNIT_DIRS="+dir)

	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("the Quadlet generator rejected the units in %s: %v\n%s", dir, err, out)
	}

	// The generator exits 0 for warnings, so its output is checked too. A
	// warning means the units work but are not what a careful author would
	// have written, which for generated files is our problem, not the user's.
	for _, line := range strings.Split(string(out), "\n") {
		lower := strings.ToLower(line)
		if strings.Contains(lower, "warning:") || strings.Contains(lower, "error") {
			t.Errorf("the generator complained about %s: %s", dir, line)
		}
	}
}
