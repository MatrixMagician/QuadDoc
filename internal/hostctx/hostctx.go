// Package hostctx describes observed facts about a system, so that findings can
// be upgraded from possible to confirmed.
//
// The interface exists from the start even though the live implementation lands
// later, because rules must be written against it and must behave sensibly when
// nothing is known. Unknown is the zero implementation: every question returns
// "not known", so a rule needs no nil checks and the no-context path is the one
// exercised by default.
//
// Live implementations read files only, never subprocesses: `/sys/fs/selinux/
// enforce`, `/proc/self/mountinfo`, `/etc/subuid`, `/etc/subgid`. That is the
// spec's guidance, and it is also what makes a captured context replayable,
// since a directory of files can be serialised but a subprocess cannot.
package hostctx

// SELinuxMode is the state of SELinux on a system.
type SELinuxMode int

const (
	// SELinuxUnknown means no host context was gathered.
	SELinuxUnknown SELinuxMode = iota
	// SELinuxDisabled means SELinux is absent from the kernel.
	SELinuxDisabled
	// SELinuxPermissive means policy is loaded but violations are logged
	// rather than denied.
	SELinuxPermissive
	// SELinuxEnforcing means policy is loaded and enforced.
	SELinuxEnforcing
)

func (m SELinuxMode) String() string {
	switch m {
	case SELinuxDisabled:
		return "disabled"
	case SELinuxPermissive:
		return "permissive"
	case SELinuxEnforcing:
		return "enforcing"
	}
	return "unknown"
}

// Mount is one entry from the mount table.
type Mount struct {
	// MountPoint is where the filesystem is mounted.
	MountPoint string
	// FSType is the filesystem type, e.g. `ext4`, `nfs4`, `fuse.sshfs`.
	// QD003 decides from this, not from a path pattern.
	FSType string
	// Options are the mount options, which may include a `context=` setting
	// that makes relabelling unnecessary or wrong.
	Options string
}

// IDRange is a subordinate UID or GID allocation from /etc/subuid or
// /etc/subgid.
type IDRange struct {
	Start int
	Count int
}

// Contains reports whether an ID falls within the range.
func (r IDRange) Contains(id int) bool {
	return id >= r.Start && id < r.Start+r.Count
}

// Context is what rules may consult about the host.
//
// Every method reports whether the fact is known, so that a rule can distinguish
// "the host says no" from "we did not look". Conflating the two is how a linter
// starts asserting things it has not checked.
type Context interface {
	// SELinux reports the SELinux mode, or SELinuxUnknown.
	SELinux() SELinuxMode

	// MountFor returns the mount entry whose mount point is the longest
	// prefix of the given path: the filesystem that path actually lives on.
	MountFor(path string) (Mount, bool)

	// SubUIDRanges and SubGIDRanges return the calling user's subordinate ID
	// allocations.
	SubUIDRanges() ([]IDRange, bool)
	SubGIDRanges() ([]IDRange, bool)

	// UnprivilegedPortStart returns net.ipv4.ip_unprivileged_port_start.
	// QD031 must read this rather than assume 1024: administrators commonly
	// lower it to 80.
	UnprivilegedPortStart() (int, bool)

	// ExistingUnitNames returns the names of units already installed in the
	// Quadlet search path, for collision detection.
	ExistingUnitNames() ([]string, bool)

	// Rootless reports whether Podman is running rootless.
	Rootless() (bool, bool)
}

// Unknown is a Context that knows nothing. It is the default, so that the
// no-host-context path is the one exercised unless the user opts in.
type Unknown struct{}

func (Unknown) SELinux() SELinuxMode                { return SELinuxUnknown }
func (Unknown) MountFor(string) (Mount, bool)       { return Mount{}, false }
func (Unknown) SubUIDRanges() ([]IDRange, bool)     { return nil, false }
func (Unknown) SubGIDRanges() ([]IDRange, bool)     { return nil, false }
func (Unknown) UnprivilegedPortStart() (int, bool)  { return 0, false }
func (Unknown) ExistingUnitNames() ([]string, bool) { return nil, false }
func (Unknown) Rootless() (bool, bool)              { return false, false }

// Static is a Context with fixed answers, for tests and for replaying a
// captured context.
type Static struct {
	SELinuxMode    SELinuxMode
	Mounts         []Mount
	SubUID         []IDRange
	SubGID         []IDRange
	PortStart      int
	PortStartKnown bool
	UnitNames      []string
	UnitNamesKnown bool
	IsRootless     bool
	RootlessKnown  bool
}

func (s Static) SELinux() SELinuxMode { return s.SELinuxMode }

// MountFor returns the longest mount point that prefixes path, which is the
// filesystem the path is actually on. A shorter match like `/` would otherwise
// shadow the specific mount the caller cares about.
func (s Static) MountFor(path string) (Mount, bool) {
	var best Mount
	var found bool
	for _, m := range s.Mounts {
		if !pathHasPrefix(path, m.MountPoint) {
			continue
		}
		if !found || len(m.MountPoint) > len(best.MountPoint) {
			best, found = m, true
		}
	}
	return best, found
}

func (s Static) SubUIDRanges() ([]IDRange, bool) {
	return s.SubUID, s.SubUID != nil
}

func (s Static) SubGIDRanges() ([]IDRange, bool) {
	return s.SubGID, s.SubGID != nil
}

func (s Static) UnprivilegedPortStart() (int, bool) {
	return s.PortStart, s.PortStartKnown
}

func (s Static) ExistingUnitNames() ([]string, bool) {
	return s.UnitNames, s.UnitNamesKnown
}

func (s Static) Rootless() (bool, bool) {
	return s.IsRootless, s.RootlessKnown
}

// pathHasPrefix reports whether path lies within dir, comparing whole path
// components so that `/var/lib2` is not treated as being under `/var/lib`.
func pathHasPrefix(path, dir string) bool {
	if dir == "/" {
		return true
	}
	if path == dir {
		return true
	}
	return len(path) > len(dir) && path[:len(dir)] == dir && path[len(dir)] == '/'
}
