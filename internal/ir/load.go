package ir

import (
	"fmt"
	"os"
	"path/filepath"
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

	section := kind.Section()
	if section == "" {
		return u
	}

	for _, e := range f.Section(section) {
		switch strings.ToLower(e.Key) {
		case "image":
			u.Image = e.Value
		case "volume":
			u.Mounts = append(u.Mounts, ParseMount(e.Value, e.Line))
		case "publishport":
			if p, ok := ParsePort(e.Value, e.Line); ok {
				u.Ports = append(u.Ports, p)
			}
		case "network":
			u.Networks = append(u.Networks, e.Value)
		case "environment":
			u.Environment = append(u.Environment, parseEnv(e.Value, e.Line)...)
		case "user":
			u.User = e.Value
		case "group":
			u.Group = e.Value
		case "groupadd":
			u.GroupAdd = append(u.GroupAdd, e.Value)
		case "userns":
			u.UserNS = e.Value
		case "autoupdate":
			u.AutoUpdate = e.Value
		case "pod":
			u.Pod = e.Value
		case "notify":
			u.Notify = e.Value
		case "healthcmd":
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
	case strings.HasPrefix(m.Source, "/"), strings.HasPrefix(m.Source, "./"),
		strings.HasPrefix(m.Source, "../"), strings.HasPrefix(m.Source, "~"),
		strings.HasPrefix(m.Source, "%"):
		// Absolute, relative, home-anchored, and systemd-specifier paths are
		// all bind mounts. Quadlet resolves a leading `.` relative to the
		// unit file's own location.
		m.Type = MountBind
	default:
		m.Type = MountNamed
	}
	return m
}

// VolumeObjectName returns the Podman volume name a named-volume source
// resolves to. Quadlet prefixes volumes it creates with `systemd-`, so
// `pg.volume` becomes `systemd-pg`. Verified against Podman 5.8.4.
func (m Mount) VolumeObjectName() string {
	if m.UnitRef != "" {
		return "systemd-" + m.UnitRef
	}
	return m.Source
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
		n, err := strconv.Atoi(strings.TrimSpace(fields[0]))
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
		} else if n, err := strconv.Atoi(strings.TrimSpace(host)); err == nil {
			p.HostPort = n
		}
		n, err := strconv.Atoi(strings.TrimSpace(container))
		if err != nil {
			return p, false
		}
		p.ContainerPort = n
		return p, true
	case 3:
		if p.HostIP == "" {
			p.HostIP = fields[0]
		}
		if n, err := strconv.Atoi(strings.TrimSpace(fields[1])); err == nil {
			p.HostPort = n
		}
		n, err := strconv.Atoi(strings.TrimSpace(fields[2]))
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
	_, err := strconv.Atoi(strings.TrimSpace(s))
	return err == nil
}

// parseEnv decomposes an `Environment=` value, which may carry several
// space-separated assignments on one line.
func parseEnv(value string, line int) []EnvVar {
	var out []EnvVar
	for _, field := range splitEnvFields(value) {
		name, val, found := strings.Cut(field, "=")
		if !found {
			continue
		}
		out = append(out, EnvVar{
			Name:  strings.TrimSpace(name),
			Value: strings.Trim(strings.TrimSpace(val), `"'`),
			Line:  line,
		})
	}
	return out
}

// splitEnvFields splits on whitespace but keeps quoted runs together, so
// `Environment=A=1 B="two words"` yields two assignments rather than three.
func splitEnvFields(value string) []string {
	var fields []string
	var cur strings.Builder
	var quote rune

	for _, r := range value {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			}
			cur.WriteRune(r)
		case r == '"' || r == '\'':
			quote = r
			cur.WriteRune(r)
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
