package hostctx

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"slices"
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
		unitPaths   []string
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

// readSubIDs reads the calling user's lines from a subuid(5) file. A file that
// opens but has no line for the user yields an empty, non-nil slice: the host
// has answered "none", which is not the same as not knowing.
func (l *Live) readSubIDs(file string) []IDRange {
	f, err := os.Open(l.path(file))
	if err != nil {
		return nil
	}
	defer f.Close()

	// When replaying a captured context the current user is not the captured
	// one, so a capture records only the relevant lines and we take them all.
	if l.Root != "" {
		return parseSubIDs(f, nil)
	}

	// Match on both the name and the numeric UID, since either may appear.
	// Without a user there is no telling which lines are ours.
	u, err := user.Current()
	if err != nil {
		return nil
	}
	return parseSubIDs(f, []string{u.Username, u.Uid})
}

// parseSubIDs parses subuid(5) format, `name:start:count` one per line, where
// the name may be a user name or a UID. It keeps the lines whose name is in
// names, or every line when names is nil.
func parseSubIDs(r io.Reader, names []string) []IDRange {
	ranges := []IDRange{}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Split(line, ":")
		if len(parts) != 3 {
			continue
		}
		if names != nil && !slices.Contains(names, parts[0]) {
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
// precedence order. Rootful and rootless Podman have separate lists, per
// podman-systemd.unit(5) (checked against Podman 5.8), sections "Podman
// rootful unit search path" and "Podman rootless unit search path".
func (l *Live) quadletSearchPath() []string {
	if rootless, _ := l.Rootless(); !rootless {
		return []string{
			"/run/containers/systemd",
			"/etc/containers/systemd",
			"/usr/share/containers/systemd",
		}
	}

	var paths []string
	if runtime := os.Getenv("XDG_RUNTIME_DIR"); runtime != "" {
		paths = append(paths, filepath.Join(runtime, "containers/systemd"))
	}
	// $XDG_CONFIG_HOME, or ~/.config when it is unset.
	if config, err := os.UserConfigDir(); err == nil {
		paths = append(paths, filepath.Join(config, "containers/systemd"))
	}
	return append(paths,
		filepath.Join("/etc/containers/systemd/users", strconv.Itoa(os.Getuid())),
		"/etc/containers/systemd/users")
}

// unitsFile is where a capture records the installed units' paths.
const unitsFile = "quaddoc-units"

// ExistingUnitPaths lists units already installed in the Quadlet search path,
// as paths on the host. A name installed in two directories appears twice,
// since either copy collides with a new unit of that name.
func (l *Live) ExistingUnitPaths() ([]string, bool) {
	if l.cache.unitsRead {
		return l.cache.unitPaths, l.cache.unitsKnown
	}
	l.cache.unitsRead = true

	if l.Root != "" {
		if data, err := os.ReadFile(filepath.Join(l.Root, unitsFile)); err == nil {
			for line := range strings.Lines(string(data)) {
				if p := strings.TrimSuffix(line, "\n"); p != "" {
					l.cache.unitPaths = append(l.cache.unitPaths, p)
				}
			}
			l.cache.unitsKnown = true
			return l.cache.unitPaths, true
		}
		// Captures made before quaddoc-units recorded empty files under
		// the search path instead, which the scan below still finds as long
		// as the replaying $HOME and UID match the capturing ones.
	}

	for _, dir := range l.quadletSearchPath() {
		entries, err := os.ReadDir(l.path(dir))
		if err != nil {
			continue
		}
		l.cache.unitsKnown = true
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			switch filepath.Ext(e.Name()) {
			case ".container", ".volume", ".network", ".pod", ".kube", ".build", ".image":
				l.cache.unitPaths = append(l.cache.unitPaths, filepath.Join(dir, e.Name()))
			}
		}
	}
	return l.cache.unitPaths, l.cache.unitsKnown
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
// diverging. The two facts that depend on who is asking, the rootless status
// and the installed units, go in quaddoc-* files at the top instead.
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

	// Unit paths, one per line in a file of their own. The contents are not
	// read, and copying them would leak whatever secrets the units contain.
	// The search path embeds $HOME and the UID, so the paths are recorded as
	// found rather than laid out for replay to re-derive in its own
	// environment.
	if paths, known := live.ExistingUnitPaths(); known {
		var b strings.Builder
		for _, p := range paths {
			b.WriteString(p + "\n")
		}
		if err := os.WriteFile(filepath.Join(dir, unitsFile), []byte(b.String()), 0o644); err != nil {
			return fmt.Errorf("recording installed units: %w", err)
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
	var known bool
	switch file {
	case "/etc/subuid":
		ranges, known = live.SubUIDRanges()
	case "/etc/subgid":
		ranges, known = live.SubGIDRanges()
	}
	if !known {
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

	if names, known := c.ExistingUnitPaths(); known {
		lines = append(lines, fmt.Sprintf("Installed Quadlet units: %d", len(names)))
	} else {
		lines = append(lines, "Installed Quadlet units: unknown")
	}

	return lines
}
