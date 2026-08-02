package hostctx

import (
	"bufio"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
)

// Live reads facts from the running system.
//
// Everything here comes from files, never subprocesses. That is the spec's
// guidance, and it is also what makes a captured context replayable: a
// directory of files can be serialised and read back, whereas a subprocess
// cannot. It also means quaddoc works with no podman binary present.
type Live struct {
	// Root is prefixed to every path read, which is what lets the same code
	// serve both the live system (Root = "") and a captured directory.
	Root string

	// cached values, so repeated rule queries do not re-read the filesystem.
	cache struct {
		selinux     *SELinuxMode
		mounts      []Mount
		mountsRead  bool
		subUID      []IDRange
		subUIDRead  bool
		subGID      []IDRange
		subGIDRead  bool
		portStart   int
		portKnown   bool
		portRead    bool
		unitNames   []string
		unitsKnown  bool
		unitsRead   bool
		rootless    bool
		rootlessSet bool
	}
}

// NewLive returns a context reading the running system.
func NewLive() *Live { return &Live{} }

// NewReplay returns a context reading a previously captured directory. The
// findings it produces are identical to those from the machine it was captured
// on, which is the whole point: capture on the broken machine, lint anywhere.
func NewReplay(dir string) *Live { return &Live{Root: dir} }

// path resolves a system path against the context root.
func (l *Live) path(p string) string {
	if l.Root == "" {
		return p
	}
	// Captured files live under the root with their absolute path preserved,
	// so /etc/subuid becomes <root>/etc/subuid.
	return filepath.Join(l.Root, p)
}

// SELinux reads the enforcement mode.
//
// The file is absent on a kernel without SELinux, which is how "disabled" is
// distinguished from "permissive": permissive has policy loaded and the file
// present containing 0.
func (l *Live) SELinux() SELinuxMode {
	if l.cache.selinux != nil {
		return *l.cache.selinux
	}

	mode := SELinuxDisabled
	if data, err := os.ReadFile(l.path("/sys/fs/selinux/enforce")); err == nil {
		if strings.TrimSpace(string(data)) == "1" {
			mode = SELinuxEnforcing
		} else {
			mode = SELinuxPermissive
		}
	}

	l.cache.selinux = &mode
	return mode
}

// MountFor returns the filesystem a path is on: the mount whose mount point is
// the longest prefix of the path.
func (l *Live) MountFor(path string) (Mount, bool) {
	l.readMounts()
	return Static{Mounts: l.cache.mounts}.MountFor(path)
}

// Mounts returns the whole mount table, for capture.
func (l *Live) Mounts() []Mount {
	l.readMounts()
	return l.cache.mounts
}

// readMounts parses /proc/self/mountinfo.
//
// The format is documented in proc(5): fields are mount ID, parent ID, device,
// root, mount point, mount options, then zero or more optional fields, a "-"
// separator, the filesystem type, the source, and the super options. The
// optional fields are why the filesystem type cannot be read at a fixed index.
func (l *Live) readMounts() {
	if l.cache.mountsRead {
		return
	}
	l.cache.mountsRead = true

	f, err := os.Open(l.path("/proc/self/mountinfo"))
	if err != nil {
		return
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 7 {
			continue
		}

		// Find the "-" that ends the optional fields.
		sep := -1
		for i := 6; i < len(fields); i++ {
			if fields[i] == "-" {
				sep = i
				break
			}
		}
		if sep < 0 || sep+2 >= len(fields) {
			continue
		}

		options := fields[5]
		if sep+3 < len(fields) {
			// Super options may carry context=, which QD003 needs.
			options += "," + fields[sep+3]
		}

		l.cache.mounts = append(l.cache.mounts, Mount{
			MountPoint: unescapeOctal(fields[4]),
			FSType:     fields[sep+1],
			Options:    options,
		})
	}
}

// unescapeOctal decodes the \040-style escapes the kernel uses for spaces and
// other awkward characters in mount points.
func unescapeOctal(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}

	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// SubUIDRanges returns the calling user's subordinate UID allocations.
func (l *Live) SubUIDRanges() ([]IDRange, bool) {
	if !l.cache.subUIDRead {
		l.cache.subUIDRead = true
		l.cache.subUID = l.readSubIDs("/etc/subuid")
	}
	return l.cache.subUID, l.cache.subUID != nil
}

// SubGIDRanges returns the calling user's subordinate GID allocations.
func (l *Live) SubGIDRanges() ([]IDRange, bool) {
	if !l.cache.subGIDRead {
		l.cache.subGIDRead = true
		l.cache.subGID = l.readSubIDs("/etc/subgid")
	}
	return l.cache.subGID, l.cache.subGID != nil
}

// readSubIDs parses subuid(5) format: `name:start:count`, one per line, where
// the name may be a user name or a UID.
func (l *Live) readSubIDs(file string) []IDRange {
	f, err := os.Open(l.path(file))
	if err != nil {
		return nil
	}
	defer f.Close()

	// Match on both the name and the numeric UID, since either may appear.
	var names []string
	if u, err := user.Current(); err == nil {
		names = append(names, u.Username, u.Uid)
	}
	// When replaying a captured context the current user is not the captured
	// one, so a capture records only the relevant lines and we take them all.
	takeAll := l.Root != ""

	var ranges []IDRange
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Split(line, ":")
		if len(parts) != 3 {
			continue
		}
		if !takeAll && !contains(names, parts[0]) {
			continue
		}

		start, err1 := strconv.Atoi(parts[1])
		count, err2 := strconv.Atoi(parts[2])
		if err1 != nil || err2 != nil {
			continue
		}
		ranges = append(ranges, IDRange{Start: start, Count: count})
	}
	return ranges
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

// UnprivilegedPortStart reads net.ipv4.ip_unprivileged_port_start from procfs
// rather than invoking sysctl, so there is no subprocess and the value can be
// captured.
func (l *Live) UnprivilegedPortStart() (int, bool) {
	if l.cache.portRead {
		return l.cache.portStart, l.cache.portKnown
	}
	l.cache.portRead = true

	data, err := os.ReadFile(l.path("/proc/sys/net/ipv4/ip_unprivileged_port_start"))
	if err != nil {
		return 0, false
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0, false
	}

	l.cache.portStart, l.cache.portKnown = n, true
	return n, true
}

// quadletSearchPath returns the directories Quadlet reads units from, in
// precedence order, as documented in podman-systemd.unit(5).
func (l *Live) quadletSearchPath() []string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = os.Getenv("HOME")
	}

	paths := []string{
		filepath.Join(home, ".config/containers/systemd"),
		filepath.Join(home, ".local/share/containers/systemd"),
		"/etc/containers/systemd/users",
		"/run/containers/systemd",
		"/etc/containers/systemd",
		"/usr/share/containers/systemd",
	}
	if config := os.Getenv("XDG_CONFIG_HOME"); config != "" {
		paths = append([]string{filepath.Join(config, "containers/systemd")}, paths...)
	}
	return paths
}

// ExistingUnitNames lists units already installed in the Quadlet search path.
func (l *Live) ExistingUnitNames() ([]string, bool) {
	if l.cache.unitsRead {
		return l.cache.unitNames, l.cache.unitsKnown
	}
	l.cache.unitsRead = true

	seen := map[string]bool{}
	for _, dir := range l.quadletSearchPath() {
		entries, err := os.ReadDir(l.path(dir))
		if err != nil {
			continue
		}
		l.cache.unitsKnown = true
		for _, e := range entries {
			if e.IsDir() || seen[e.Name()] {
				continue
			}
			switch filepath.Ext(e.Name()) {
			case ".container", ".volume", ".network", ".pod", ".kube", ".build", ".image":
				seen[e.Name()] = true
				l.cache.unitNames = append(l.cache.unitNames, e.Name())
			}
		}
	}
	return l.cache.unitNames, l.cache.unitsKnown
}

// Rootless reports whether Podman would run rootless, which is simply whether
// the effective user is root.
func (l *Live) Rootless() (bool, bool) {
	if l.cache.rootlessSet {
		return l.cache.rootless, true
	}

	// When replaying, the answer was recorded at capture time.
	if l.Root != "" {
		data, err := os.ReadFile(l.path("/quaddoc-rootless"))
		if err != nil {
			return false, false
		}
		l.cache.rootless = strings.TrimSpace(string(data)) == "true"
		l.cache.rootlessSet = true
		return l.cache.rootless, true
	}

	l.cache.rootless = os.Geteuid() != 0
	l.cache.rootlessSet = true
	return l.cache.rootless, true
}

// Capture writes the live context to a directory, so it can be replayed
// elsewhere. Capture on the machine where something is wrong, lint on your own.
//
// The files keep their original paths under the directory, so replay is the
// same code reading the same layout, which is what keeps live and replay from
// diverging.
func Capture(dir string) error {
	live := NewLive()

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("creating %s: %w", dir, err)
	}

	// Copy the files the live reader consults.
	for _, file := range []string{
		"/sys/fs/selinux/enforce",
		"/proc/self/mountinfo",
		"/proc/sys/net/ipv4/ip_unprivileged_port_start",
	} {
		if err := copyInto(dir, file); err != nil {
			return err
		}
	}

	// The subordinate ID files hold every user's allocation, so capture only
	// the calling user's lines: the rest is not ours to carry around.
	if err := captureSubIDs(dir, "/etc/subuid", live); err != nil {
		return err
	}
	if err := captureSubIDs(dir, "/etc/subgid", live); err != nil {
		return err
	}

	// Unit names, recorded as empty files so replay's directory listing works
	// unchanged. The contents are not read, and copying them would leak
	// whatever secrets the units contain.
	//
	// They go under the first search-path directory, resolved the same way
	// the live reader resolves it, so that replay finds them without any
	// special case.
	names, known := live.ExistingUnitNames()
	if known {
		unitDir := filepath.Join(dir, live.quadletSearchPath()[0])
		if err := os.MkdirAll(unitDir, 0o755); err != nil {
			return fmt.Errorf("creating %s: %w", unitDir, err)
		}
		for _, name := range names {
			if err := os.WriteFile(filepath.Join(unitDir, name), nil, 0o644); err != nil {
				return fmt.Errorf("recording unit name %s: %w", name, err)
			}
		}
	}

	rootless, _ := live.Rootless()
	if err := os.WriteFile(filepath.Join(dir, "quaddoc-rootless"),
		[]byte(strconv.FormatBool(rootless)+"\n"), 0o644); err != nil {
		return fmt.Errorf("recording rootless status: %w", err)
	}

	return nil
}

// copyInto copies a system file into the capture directory, preserving its
// path. A file that does not exist is not an error: its absence is itself a
// fact, and replay will read the same absence.
func copyInto(dir, file string) error {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil
	}

	dest := filepath.Join(dir, file)
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return fmt.Errorf("creating %s: %w", filepath.Dir(dest), err)
	}
	if err := os.WriteFile(dest, data, 0o644); err != nil {
		return fmt.Errorf("writing %s: %w", dest, err)
	}
	return nil
}

// captureSubIDs records only the calling user's subordinate ranges.
func captureSubIDs(dir, file string, live *Live) error {
	var ranges []IDRange
	switch file {
	case "/etc/subuid":
		ranges, _ = live.SubUIDRanges()
	case "/etc/subgid":
		ranges, _ = live.SubGIDRanges()
	}
	if ranges == nil {
		return nil
	}

	var b strings.Builder
	b.WriteString("# Captured by quaddoc: the invoking user's ranges only.\n")
	for _, r := range ranges {
		fmt.Fprintf(&b, "captured:%d:%d\n", r.Start, r.Count)
	}

	dest := filepath.Join(dir, file)
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return fmt.Errorf("creating %s: %w", filepath.Dir(dest), err)
	}
	if err := os.WriteFile(dest, []byte(b.String()), 0o644); err != nil {
		return fmt.Errorf("writing %s: %w", dest, err)
	}
	return nil
}

// Describe summarises a context for `quaddoc doctor`.
func Describe(c Context) []string {
	lines := []string{"SELinux: " + c.SELinux().String()}

	if rootless, known := c.Rootless(); known {
		mode := "rootful"
		if rootless {
			mode = "rootless"
		}
		lines = append(lines, "Podman mode: "+mode)
	} else {
		lines = append(lines, "Podman mode: unknown")
	}

	if ranges, known := c.SubUIDRanges(); known {
		total := 0
		for _, r := range ranges {
			total += r.Count
		}
		lines = append(lines, fmt.Sprintf("Subordinate UIDs: %d available", total))
	} else {
		lines = append(lines, "Subordinate UIDs: unknown")
	}

	if port, known := c.UnprivilegedPortStart(); known {
		lines = append(lines, fmt.Sprintf("Unprivileged ports: from %d", port))
	} else {
		lines = append(lines, "Unprivileged ports: unknown")
	}

	if names, known := c.ExistingUnitNames(); known {
		lines = append(lines, fmt.Sprintf("Installed Quadlet units: %d", len(names)))
	} else {
		lines = append(lines, "Installed Quadlet units: unknown")
	}

	return lines
}
