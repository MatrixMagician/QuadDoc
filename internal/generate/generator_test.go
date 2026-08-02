package generate

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
)

// quadletGenerator locates Podman's Quadlet generator, which is not on PATH.
//
// It also enforces the project's documented minimum. ADR-0002 sets that at
// Podman 5.0, and keys such as Pod= do not exist before it, so running the
// acceptance tests against an older generator reports failures that are really
// the runner's age rather than a bug in the units. Ubuntu's packaged Podman was
// old enough to fail exactly this way in CI.
func quadletGenerator(t *testing.T) string {
	t.Helper()

	var path string
	for _, candidate := range []string{
		"/usr/libexec/podman/quadlet",
		"/usr/lib/podman/quadlet",
		"/usr/local/libexec/podman/quadlet",
	} {
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			path = candidate
			break
		}
	}
	if path == "" {
		t.Skip("Quadlet generator not installed; skipping the real-generator check")
	}

	major, minor, ok := podmanVersion()
	if !ok {
		t.Skipf("cannot determine the Podman version for %s; skipping", path)
	}
	if major < 5 {
		t.Skipf("Podman %d.%d is older than the supported minimum of 5.0 (ADR-0002); skipping",
			major, minor)
	}
	return path
}

// podmanVersion reports the installed Podman version.
func podmanVersion() (major, minor int, ok bool) {
	out, err := exec.Command("podman", "--version").Output()
	if err != nil {
		return 0, 0, false
	}

	fields := strings.Fields(string(out))
	if len(fields) < 3 {
		return 0, 0, false
	}

	parts := strings.SplitN(strings.TrimSpace(fields[2]), ".", 3)
	if len(parts) < 2 {
		return 0, 0, false
	}
	major, err1 := strconv.Atoi(parts[0])
	minor, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil {
		return 0, 0, false
	}
	return major, minor, true
}
