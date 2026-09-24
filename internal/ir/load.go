package ir

import (
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/MatrixMagician/quaddoc/internal/parse/quadlet"
)

// LoadProject reads every Quadlet unit under root into a project.
//
// Files whose extension is not a Quadlet unit type are ignored, so pointing
// quaddoc at a directory containing a README or a compose file is harmless.
func LoadProject(root string) (*Project, error) {
	info, err := os.Stat(root)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", root, err)
	}

	var paths []string
	if info.IsDir() {
		entries, err := os.ReadDir(root)
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", root, err)
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			p := filepath.Join(root, e.Name())
			if KindFromPath(p) != KindUnknown {
				paths = append(paths, p)
			}
		}
	} else {
		// A single file named explicitly is loaded whatever its extension:
		// the user asked for it by name, so refusing would be unhelpful.
		paths = append(paths, root)
		root = filepath.Dir(root)
	}

	p := &Project{Root: root}
	for _, path := range paths {
		u, err := LoadUnit(path)
		if err != nil {
			return nil, err
		}
		p.Units = append(p.Units, u)
	}
	p.Sort()
	return p, nil
}

// LoadUnit reads and normalises one Quadlet unit file.
func LoadUnit(path string) (*Unit, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening %s: %w", path, err)
	}
	defer f.Close()

	parsed, err := quadlet.Parse(path, f)
	if err != nil {
		return nil, err
	}
	return FromParsed(parsed), nil
}

// FromParsed normalises an already-parsed unit file.
func FromParsed(f *quadlet.File) *Unit {
	base := filepath.Base(f.Path)
	kind := KindFromPath(base)

	u := &Unit{
		Path:   f.Path,
		Name:   strings.TrimSuffix(base, filepath.Ext(base)),
		Kind:   kind,
		Source: f,
	}

	for _, e := range f.Entries() {
		u.Entries = append(u.Entries, SourceEntry{
			Section: e.Section, Key: e.Key, Value: e.Value, Line: e.Line,
		})
	}

	section := kind.Section()
	if section == "" {
		return u
	}

	for _, e := range f.Section(section) {
		u.SetKeyLine(e.Key, e.Line)
		// An empty assignment resets a list-valued key (systemd.syntax(7));
		// the generator honours this for every list modelled here.
		if e.Value == "" {
			switch e.Key {
			case "Volume", "Mount":
				// Each key resets only its own entries. Verified against
				// Podman 5.8.4.
				u.Mounts = slices.DeleteFunc(u.Mounts, func(m Mount) bool { return m.Key() == e.Key })
				continue
			case "PublishPort":
				u.Ports = nil
				continue
			case "Network":
				u.Networks = nil
				continue
			case "Environment":
				u.Environment = nil
				continue
			case "GroupAdd":
				u.GroupAdd = nil
				continue
			}
		}
		switch e.Key {
		case "Image":
			u.Image = e.Value
		case "Volume":
			u.Mounts = append(u.Mounts, ParseMount(e.Value, e.Line))
		case "Mount":
			if m, ok := ParseMountKey(e.Value, e.Line); ok {
				u.Mounts = append(u.Mounts, m)
			}
		case "PublishPort":
			if p, ok := ParsePort(e.Value, e.Line); ok {
				u.Ports = append(u.Ports, p)
			}
		case "Network":
			u.Networks = append(u.Networks, e.Value)
		case "Environment":
			u.Environment = append(u.Environment, parseEnv(e.Value, e.Line)...)
		case "User":
			u.User = e.Value
		case "Group":
			u.Group = e.Value
		case "GroupAdd":
			u.GroupAdd = append(u.GroupAdd, e.Value)
		case "UserNS":
			u.UserNS = e.Value
		case "AutoUpdate":
			u.AutoUpdate = e.Value
		case "Pod":
			u.Pod = e.Value
		case "Notify":
			u.Notify = e.Value
		case "HealthCmd":
			u.HasHealthCmd = e.Value != "" && e.Value != "none"
		}
	}

	// Restart lives in [Service]: it is a systemd key, not a Quadlet one, and
	// Quadlet passes the section through untouched.
	if v, ok := f.Lookup("Service", "Restart"); ok {
		u.Restart = v
	}

	u.HasInstall = f.HasSection("Install")
	for _, e := range f.Section("Install") {
		u.InstallKeys = append(u.InstallKeys, KeyValue{Key: e.Key, Value: e.Value, Line: e.Line})
	}

	return u
}

// ParseMount decomposes one `Volume=` value.
//
// The grammar is `[[SOURCE-VOLUME|HOST-DIR:]CONTAINER-DIR[:OPTIONS]]`
// (podman-systemd.unit(5)). A source that ends in `.volume` refers to a sibling
// Quadlet unit, which Podman materialises as a volume named `systemd-$name`.
func ParseMount(value string, line int) Mount {
	m := Mount{Line: line, Raw: value}

	parts := strings.Split(value, ":")
	switch len(parts) {
	case 0:
		return m
	case 1:
		// `Volume=/data` is an anonymous volume at that destination.
		m.Destination = parts[0]
		m.Type = MountAnonymous
		return m
	case 2:
		m.Source, m.Destination = parts[0], parts[1]
	default:
		// Options are only ever the final field, so anything between the
		// first and last colon belongs to a path containing colons.
		m.Source = parts[0]
		m.Destination = strings.Join(parts[1:len(parts)-1], ":")
		for _, o := range strings.Split(parts[len(parts)-1], ",") {
			if o = strings.TrimSpace(o); o != "" {
				m.Options = append(m.Options, o)
			}
		}
	}

	switch {
	case strings.HasSuffix(m.Source, ".volume"):
		m.Type = MountNamed
		m.UnitRef = strings.TrimSuffix(m.Source, ".volume")
	case strings.HasPrefix(m.Source, "/"), strings.HasPrefix(m.Source, "."),
		strings.HasPrefix(m.Source, "~"), strings.HasPrefix(m.Source, "%"):
		// Absolute, relative, home-anchored, and systemd-specifier paths are
		// all bind mounts. Quadlet resolves a leading `.` relative to the
		// unit file's own location.
		m.Type = MountBind
	default:
		m.Type = MountNamed
	}
	return m
}

// ParseMountKey decomposes one `Mount=` value, reporting false for anything
// other than a bind mount podman would accept.
//
// The grammar is podman-run(1) --mount's `type=TYPE,KEY[=VALUE],...`, which
// Quadlet reads as CSV. Quadlet defaults a missing type to volume and matches
// `type=bind` exactly. Options are normalised to their Volume= spelling so the
// rules see one vocabulary: relabel=private is Z, relabel=shared is z, U or
// chown is U, and ro or readonly is ro. podman treats a boolean as set only
// when it is bare or "true" in any case, so `ro=1` is read-write. Verified
// against Podman 5.8.4 with quadlet -dryrun and podman create/inspect.
func ParseMountKey(value string, line int) (Mount, bool) {
	fields, err := csv.NewReader(strings.NewReader(value)).Read()
	if err != nil {
		return Mount{}, false
	}

	m := Mount{Line: line, Raw: value, Type: MountBind}
	var bind bool
	for _, field := range fields {
		k, v, hasValue := strings.Cut(field, "=")
		set := !hasValue || strings.EqualFold(v, "true")
		switch k {
		case "type":
			bind = v == "bind"
		case "src", "source":
			m.Source = v
		case "dst", "dest", "destination", "target":
			m.Destination = v
		case "relabel":
			switch v {
			case "private":
				m.Options = append(m.Options, "Z")
			case "shared":
				m.Options = append(m.Options, "z")
			default:
				// podman refuses the mount, so there is nothing to audit.
				return Mount{}, false
			}
		case "U", "chown":
			if set {
				m.Options = append(m.Options, "U")
			}
		case "ro", "readonly":
			if set {
				m.Options = append(m.Options, "ro")
			}
		default:
			m.Options = append(m.Options, field)
		}
	}
	return m, bind && m.Source != "" && m.Destination != ""
}

// MountKeySpelling gives the `Mount=` spelling of a normalised option, for
// writing a remediation in the form the user wrote. podman-run(1) --mount.
var MountKeySpelling = map[string]string{"Z": "relabel=private", "z": "relabel=shared", "U": "U=true", "ro": "ro"}

// Key names the key that declared the mount, `Mount` or `Volume`.
//
// It is derived from Raw: a Volume= value parses as a Mount= bind only if its
// comma-separated fields include `type=bind` and a source, which takes a volume
// name podman rejects or paths containing `,type=bind`.
func (m Mount) Key() string {
	if _, ok := ParseMountKey(m.Raw, m.Line); ok {
		return "Mount"
	}
	return "Volume"
}

// VolumeObjectName returns the Podman volume name a named-volume source
// resolves to when the referenced unit sets no VolumeName=. Quadlet prefixes
// volumes it creates with `systemd-`, so `pg.volume` becomes `systemd-pg`.
// Verified against Podman 5.8.4. The .volume unit's ObjectName is the name
// whatever the unit sets.
func (m Mount) VolumeObjectName() string {
	if m.UnitRef != "" {
		return "systemd-" + m.UnitRef
	}
	return m.Source
}

// ObjectName returns the name of the Podman object a .volume or .network unit
// creates: its VolumeName= or NetworkName= when set, otherwise Quadlet's
// default of `systemd-` and the unit name (podman-systemd.unit(5)). Verified
// against Podman 5.8.4. Other kinds return "".
func (u *Unit) ObjectName() string {
	key := map[UnitKind]string{KindVolume: "VolumeName", KindNetwork: "NetworkName"}[u.Kind]
	if key == "" {
		return ""
	}
	if u.Source != nil {
		// The last assignment wins, as it does for systemd.
		if vs := u.Source.Values(u.Kind.Section(), key); len(vs) > 0 && vs[len(vs)-1] != "" {
			return vs[len(vs)-1]
		}
	}
	return "systemd-" + u.Name
}

// ParsePort decomposes one `PublishPort=` value.
//
// The grammar is `[[ip:][hostPort]:]containerPort[/protocol]`, so the host port
// is the second-to-last colon-separated field when there is more than one.
func ParsePort(value string, line int) (Port, bool) {
	p := Port{Line: line, Raw: value, Protocol: "tcp"}

	spec := value
	if i := strings.LastIndex(spec, "/"); i >= 0 {
		p.Protocol = strings.ToLower(spec[i+1:])
		spec = spec[:i]
	}

	fields := strings.Split(spec, ":")
	// An IPv6 host address contains colons of its own and is bracketed;
	// treat anything bracketed as the address and parse the remainder.
	if strings.HasPrefix(spec, "[") {
		if end := strings.Index(spec, "]"); end >= 0 {
			p.HostIP = spec[1:end]
			fields = strings.Split(strings.TrimPrefix(spec[end+1:], ":"), ":")
		}
	}

	switch len(fields) {
	case 1:
		// Container port only: Podman picks a random host port.
		n, err := portNumber(fields[0])
		if err != nil {
			return p, false
		}
		p.ContainerPort = n
		return p, true
	case 2:
		host, container := fields[0], fields[1]
		if p.HostIP == "" && !isNumeric(host) && host != "" {
			// A bare address with no host port, e.g. `127.0.0.1::80`.
			p.HostIP = host
		} else if n, err := portNumber(host); err == nil {
			p.HostPort = n
		}
		n, err := portNumber(container)
		if err != nil {
			return p, false
		}
		p.ContainerPort = n
		return p, true
	case 3:
		if p.HostIP == "" {
			p.HostIP = fields[0]
		}
		if n, err := portNumber(fields[1]); err == nil {
			p.HostPort = n
		}
		n, err := portNumber(fields[2])
		if err != nil {
			return p, false
		}
		p.ContainerPort = n
		return p, true
	}
	return p, false
}

func isNumeric(s string) bool {
	if s == "" {
		return false
	}
	_, err := portNumber(s)
	return err == nil
}

// portNumber parses one port field. A range such as `80-81` yields its low
// bound, which is the port a privilege check cares about.
func portNumber(s string) (int, error) {
	low, _, _ := strings.Cut(strings.TrimSpace(s), "-")
	return strconv.Atoi(low)
}

// parseEnv decomposes an `Environment=` value, which may carry several
// space-separated assignments on one line, each optionally quoted per
// systemd.syntax(7) (either the value alone or the whole NAME=value pair).
func parseEnv(value string, line int) []EnvVar {
	var out []EnvVar
	for _, field := range splitEnvFields(value) {
		name, val, found := strings.Cut(field, "=")
		if !found {
			continue
		}
		out = append(out, EnvVar{Name: name, Value: val, Line: line})
	}
	return out
}

// splitEnvFields splits value into already-unquoted `name=value` words per
// systemd.syntax(7): whitespace separates assignments unless inside a quoted
// run, and a backslash escapes the following character, including a quote,
// which then does not end the run. Verified against Podman 5.8.4's Quadlet
// generator (`quadlet -dryrun`): `A="x y" B=z`, `"K=v w"` and
// `Q="say \"hi\""` each split and unquote exactly as its `--env` argument
// does. Quotes and escaping backslashes are consumed, not kept, so the
// result needs no further trimming.
func splitEnvFields(value string) []string {
	var fields []string
	var cur strings.Builder
	var quote rune
	escaped := false

	for _, r := range value {
		switch {
		case escaped:
			cur.WriteRune(r)
			escaped = false
		case r == '\\':
			escaped = true
		case quote != 0:
			if r == quote {
				quote = 0
			} else {
				cur.WriteRune(r)
			}
		case r == '"' || r == '\'':
			quote = r
		case r == ' ' || r == '\t':
			if cur.Len() > 0 {
				fields = append(fields, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteRune(r)
		}
	}
	if cur.Len() > 0 {
		fields = append(fields, cur.String())
	}
	return fields
}
