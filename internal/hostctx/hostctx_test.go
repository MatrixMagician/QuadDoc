package hostctx

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestLiveMatchesTheReferencePlatform checks the reader against the machine it
// is running on. It asserts internal consistency rather than specific values,
// so it holds on any Linux box, while still exercising the real files.
func TestLiveReadsThisSystem(t *testing.T) {
	live := NewLive()

	// SELinux is one of the three known states; the reader must never return
	// Unknown, since it has actually looked.
	if mode := live.SELinux(); mode == SELinuxUnknown {
		t.Error("the live reader should always reach a conclusion about SELinux")
	}

	// Every Linux system has a mount table with a root filesystem.
	if m, ok := live.MountFor("/"); !ok || m.FSType == "" {
		t.Errorf("no filesystem found for /: %+v", m)
	}

	// Rootlessness is always knowable: it is just the effective UID.
	if _, known := live.Rootless(); !known {
		t.Error("rootless status should always be known on the live system")
	}
}

func TestMountForPicksTheLongestPrefix(t *testing.T) {
	// A path is on the most specific filesystem that contains it. Matching a
	// shorter mount point would attribute a file to the wrong filesystem, and
	// QD003 would then reason about the wrong thing.
	c := Static{Mounts: []Mount{
		{MountPoint: "/", FSType: "btrfs"},
		{MountPoint: "/home", FSType: "ext4"},
		{MountPoint: "/home/user/nfs", FSType: "nfs4"},
	}}

	tests := map[string]string{
		"/etc/passwd":             "btrfs",
		"/home/user/file":         "ext4",
		"/home/user/nfs/file":     "nfs4",
		"/home/user/nfs":          "nfs4",
		"/home/user/nfsnotreally": "ext4", // not a path-component match
	}

	for path, want := range tests {
		t.Run(path, func(t *testing.T) {
			m, ok := c.MountFor(path)
			if !ok {
				t.Fatalf("no mount found for %s", path)
			}
			if m.FSType != want {
				t.Errorf("MountFor(%s) = %s, want %s", path, m.FSType, want)
			}
		})
	}
}

func TestMountForPicksTheLaterOfTwoMountsOnOnePoint(t *testing.T) {
	// The kernel lists mounts in mount order, and a later mount on the same
	// point hides the earlier one. Picking the first would put this path on
	// ext4 when it is really on NFS, and QD003 would stay silent.
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "proc/self/mountinfo"),
		"22 1 0:20 / / rw,relatime shared:1 - ext4 /dev/sda1 rw\n"+
			"40 22 8:2 / /mnt/data rw,relatime shared:5 - ext4 /dev/sdb1 rw\n"+
			"41 22 0:45 / /mnt/data rw,relatime shared:9 - nfs4 nas:/export/data rw,vers=4.2\n")

	m, ok := NewReplay(dir).MountFor("/mnt/data/app")
	if !ok || m.FSType != "nfs4" {
		t.Errorf("MountFor(/mnt/data/app) = %q/%v, want nfs4/true", m.FSType, ok)
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestUnescapeOctal(t *testing.T) {
	// The kernel escapes awkward characters in mount points, so a path with a
	// space arrives as /mnt/my\040disk.
	tests := map[string]string{
		`/mnt/plain`:      "/mnt/plain",
		`/mnt/my\040disk`: "/mnt/my disk",
		`/mnt/a\011b`:     "/mnt/a\tb",
	}
	for in, want := range tests {
		if got := unescapeOctal(in); got != want {
			t.Errorf("unescapeOctal(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestCaptureThenReplayMatchesLive is the acceptance test for capture/replay.
//
// The value of a captured context is that it produces the same answers as the
// machine it came from. If replay diverged from live, every context-dependent
// finding would become untrustworthy, so this compares every fact the interface
// exposes.
func TestCaptureThenReplayMatchesLive(t *testing.T) {
	dir := t.TempDir()
	if err := Capture(dir); err != nil {
		t.Fatalf("capturing: %v", err)
	}

	live := NewLive()
	replay := NewReplay(dir)

	if live.SELinux() != replay.SELinux() {
		t.Errorf("SELinux: live = %v, replay = %v", live.SELinux(), replay.SELinux())
	}

	liveRootless, _ := live.Rootless()
	replayRootless, replayKnown := replay.Rootless()
	if !replayKnown {
		t.Error("replay does not know the rootless status")
	} else if liveRootless != replayRootless {
		t.Errorf("rootless: live = %v, replay = %v", liveRootless, replayRootless)
	}

	livePort, liveKnown := live.UnprivilegedPortStart()
	replayPort, replayPortKnown := replay.UnprivilegedPortStart()
	if liveKnown != replayPortKnown || livePort != replayPort {
		t.Errorf("unprivileged port start: live = %d/%v, replay = %d/%v",
			livePort, liveKnown, replayPort, replayPortKnown)
	}

	// Subordinate ranges are captured as totals, since the user names differ
	// between the capturing and replaying machines.
	liveTotal := totalIDs(live.SubUIDRanges())
	replayTotal := totalIDs(replay.SubUIDRanges())
	if liveTotal != replayTotal {
		t.Errorf("subordinate UIDs: live = %d, replay = %d", liveTotal, replayTotal)
	}

	// The mount table drives QD003, so a path must land on the same
	// filesystem in both.
	for _, path := range []string{"/", "/tmp", "/home"} {
		liveMount, liveOK := live.MountFor(path)
		replayMount, replayOK := replay.MountFor(path)
		if liveOK != replayOK || liveMount.FSType != replayMount.FSType {
			t.Errorf("MountFor(%s): live = %s/%v, replay = %s/%v",
				path, liveMount.FSType, liveOK, replayMount.FSType, replayOK)
		}
	}

	liveNames, liveNamesKnown := live.ExistingUnitNames()
	replayNames, replayNamesKnown := replay.ExistingUnitNames()
	if liveNamesKnown != replayNamesKnown {
		t.Errorf("unit names known: live = %v, replay = %v", liveNamesKnown, replayNamesKnown)
	}
	if len(liveNames) != len(replayNames) {
		t.Errorf("unit names: live has %d, replay has %d", len(liveNames), len(replayNames))
	}
}

func TestCaptureDoesNotCopyUnitContents(t *testing.T) {
	// A captured context is meant to be sent to someone else. Unit files hold
	// environment variables and secret references, so only their names are
	// recorded.
	dir := t.TempDir()
	if err := Capture(dir); err != nil {
		t.Fatalf("capturing: %v", err)
	}

	var checked int
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		switch filepath.Ext(path) {
		case ".container", ".volume", ".network", ".pod":
			checked++
			if info.Size() != 0 {
				t.Errorf("%s was captured with %d bytes of content; only names should be recorded",
					path, info.Size())
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking the capture: %v", err)
	}
	t.Logf("checked %d recorded unit names", checked)
}

func TestReplayOfAnEmptyDirectoryKnowsNothing(t *testing.T) {
	// A directory that is not a capture should not be mistaken for one that
	// says "SELinux is disabled".
	replay := NewReplay(t.TempDir())

	if _, known := replay.Rootless(); known {
		t.Error("an empty directory should not report a rootless status")
	}
	if _, known := replay.UnprivilegedPortStart(); known {
		t.Error("an empty directory should not report a port threshold")
	}
	if ranges, known := replay.SubUIDRanges(); known {
		t.Errorf("an empty directory should not report subordinate ranges, got %+v", ranges)
	}
}

func TestNoSubIDEntryIsKnownToBeNone(t *testing.T) {
	// A readable /etc/subuid with no line for this user is the host saying
	// "none", which is exactly when QD013 must speak. Reporting it as unknown
	// silences the rule on the one host where it matters.
	got := parseSubIDs(strings.NewReader("# comment\nbob:100000:65536\n"), []string{"alice", "1000"})
	if got == nil || len(got) != 0 {
		t.Errorf("parseSubIDs with no matching line = %#v, want a known, empty []IDRange{}", got)
	}

	// Capture must carry "known, none" across, rather than dropping the file
	// and turning it back into "unknown".
	src := t.TempDir()
	writeFile(t, filepath.Join(src, "etc/subuid"), "# no ranges\n")
	dst := t.TempDir()
	if err := captureSubIDs(dst, "/etc/subuid", NewReplay(src)); err != nil {
		t.Fatal(err)
	}
	ranges, known := NewReplay(dst).SubUIDRanges()
	if !known || len(ranges) != 0 {
		t.Errorf("replayed SubUIDRanges = %v/%v, want none/true", ranges, known)
	}
}

func TestUnknownKnowsNothing(t *testing.T) {
	// Every question must be answerable as "not known", so that rules can
	// distinguish a negative answer from an absent one.
	var c Context = Unknown{}

	if c.SELinux() != SELinuxUnknown {
		t.Error("Unknown should report SELinuxUnknown")
	}
	if _, ok := c.MountFor("/"); ok {
		t.Error("Unknown should know no mounts")
	}
	if _, ok := c.SubUIDRanges(); ok {
		t.Error("Unknown should know no subordinate ranges")
	}
	if _, ok := c.UnprivilegedPortStart(); ok {
		t.Error("Unknown should know no port threshold")
	}
	if _, ok := c.ExistingUnitNames(); ok {
		t.Error("Unknown should know no unit names")
	}
	if _, ok := c.Rootless(); ok {
		t.Error("Unknown should not know the rootless status")
	}
}

func TestIDRangeContains(t *testing.T) {
	r := IDRange{Start: 100000, Count: 65536}

	tests := map[int]bool{
		99999:  false,
		100000: true,
		165535: true,
		165536: false,
	}
	for id, want := range tests {
		if got := r.Contains(id); got != want {
			t.Errorf("IDRange{100000, 65536}.Contains(%d) = %v, want %v", id, got, want)
		}
	}
}

func TestDescribeCoversEveryFact(t *testing.T) {
	// `quaddoc doctor` renders this, so a fact missing here is a fact the
	// user cannot see.
	lines := Describe(Static{
		SELinuxMode:    SELinuxEnforcing,
		SubUID:         []IDRange{{Start: 100000, Count: 65536}},
		PortStart:      1024,
		PortStartKnown: true,
		UnitNames:      []string{"a.container"},
		UnitNamesKnown: true,
		IsRootless:     true,
		RootlessKnown:  true,
	})

	if len(lines) != 5 {
		t.Errorf("Describe returned %d lines, want 5: %v", len(lines), lines)
	}
	for _, want := range []string{"SELinux", "Podman mode", "Subordinate UIDs",
		"Unprivileged ports", "Installed Quadlet units"} {
		found := false
		for _, line := range lines {
			if len(line) >= len(want) && line[:len(want)] == want {
				found = true
			}
		}
		if !found {
			t.Errorf("Describe omits %q: %v", want, lines)
		}
	}
}

func totalIDs(ranges []IDRange, _ bool) int {
	total := 0
	for _, r := range ranges {
		total += r.Count
	}
	return total
}
