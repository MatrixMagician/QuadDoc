// Package compose loads docker-compose projects into the IR.
//
// The compose-spec loader does the parsing, so QuadDoc inherits its handling of
// interpolation, extends, merge order, and the rest. What this package adds is
// the mapping onto Quadlet's model, and honesty about what does not map: an
// unsupported key produces a finding, never a silent drop.
package compose

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/compose-spec/compose-go/v2/loader"
	"github.com/compose-spec/compose-go/v2/types"
)

// Project is a loaded compose project, together with what could not be
// translated.
type Project struct {
	// Name is the compose project name, used to name the generated network.
	Name string
	// Services are the compose services, sorted by name for determinism.
	Services []Service
	// Volumes are the declared named volumes, sorted.
	Volumes []Volume
	// Networks are the declared networks, sorted.
	Networks []Network
	// Unsupported records compose features that have no faithful Quadlet
	// translation, so they can be reported rather than dropped.
	Unsupported []Unsupported
	// WorkingDir is the directory the compose file was loaded from.
	WorkingDir string
}

// Service is one compose service.
type Service struct {
	Name        string
	Image       string
	Command     []string
	Entrypoint  []string
	User        string
	WorkingDir  string
	Hostname    string
	Restart     string
	Environment []EnvVar
	Volumes     []Mount
	Ports       []Port
	Networks    []string
	DependsOn   []Dependency
	HealthCheck *HealthCheck
	CapAdd      []string
	CapDrop     []string
	Devices     []string
	DNS         []string
	Labels      map[string]string
	GroupAdd    []string
	ReadOnly    bool
	Privileged  bool
	ShmSize     string
	StopSignal  string
	Sysctls     map[string]string
	Tmpfs       []string
}

// EnvVar is one environment assignment.
type EnvVar struct {
	Name  string
	Value string
}

// Mount is one volume entry, already resolved by the compose loader.
type Mount struct {
	// Type is `bind`, `volume`, or `tmpfs`.
	Type string
	// Source is an absolute host path for a bind, or a volume name.
	Source string
	Target string
	// ReadOnly is the `:ro` flag.
	ReadOnly bool
	// SELinux carries a `z` or `Z` if the compose file already set one.
	SELinux string
}

// Port is one published port.
type Port struct {
	HostIP    string
	Published string
	Target    int
	Protocol  string
}

// Dependency is one `depends_on` edge.
type Dependency struct {
	Service string
	// Condition is `service_started`, `service_healthy`, or
	// `service_completed_successfully`.
	Condition string
}

// HealthCheck is a compose healthcheck.
type HealthCheck struct {
	Test        []string
	Interval    string
	Timeout     string
	StartPeriod string
	Retries     int
	Disabled    bool
}

// Volume is a declared named volume.
type Volume struct {
	Name     string
	Driver   string
	Options  map[string]string
	Labels   map[string]string
	External bool
}

// Network is a declared network.
type Network struct {
	Name     string
	Driver   string
	Internal bool
	Labels   map[string]string
	External bool
	// Subnets are the configured IPAM subnets.
	Subnets []string
	Gateway string
}

// Unsupported is a compose feature with no faithful Quadlet translation.
type Unsupported struct {
	// Service is the service it appeared on, empty for a top-level key.
	Service string
	// Key is the compose key, e.g. `build`.
	Key string
	// Reason explains why it cannot be translated, and what to do instead.
	Reason string
}

// Load reads a compose file and normalises it.
func Load(path string) (*Project, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolving %s: %w", path, err)
	}
	content, err := os.ReadFile(abs)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", abs, err)
	}

	workingDir := filepath.Dir(abs)
	// The project name defaults to the directory name, matching compose.
	name := sanitiseName(filepath.Base(workingDir))

	cfg, err := loader.LoadWithContext(context.Background(), types.ConfigDetails{
		WorkingDir:  workingDir,
		ConfigFiles: []types.ConfigFile{{Filename: abs, Content: content}},
		Environment: environment(),
	}, func(o *loader.Options) {
		o.SetProjectName(name, true)
		// Resolve paths so that bind sources are absolute, which the SELinux
		// rules need in order to reason about the filesystem they live on.
		o.ResolvePaths = true
	})
	if err != nil {
		return nil, fmt.Errorf("loading %s: %w", path, err)
	}

	return normalise(cfg, name, workingDir), nil
}

// environment gathers the process environment for interpolation, matching what
// compose itself does.
func environment() map[string]string {
	env := map[string]string{}
	for _, kv := range os.Environ() {
		if k, v, ok := strings.Cut(kv, "="); ok {
			env[k] = v
		}
	}
	return env
}

func normalise(cfg *types.Project, name, workingDir string) *Project {
	p := &Project{Name: name, WorkingDir: workingDir}

	// A service carrying `profiles:` is not active under the default profile,
	// so the loader files it under DisabledServices. Converting it silently
	// would be wrong, but so would ignoring it: the user would get a unit
	// directory quietly missing a service. Report it and move on.
	for _, svc := range cfg.DisabledServices {
		p.Unsupported = append(p.Unsupported, unsupportedFor(svc)...)
		p.Unsupported = append(p.Unsupported, Unsupported{
			Service: svc.Name,
			Key:     "profiles",
			Reason: fmt.Sprintf("service %q is only active under profile(s) %s, and systemd "+
				"has no equivalent of a compose profile. No unit was generated. Convert "+
				"with the profile enabled if you want one, or keep profile variants in "+
				"separate directories.", svc.Name, strings.Join(svc.Profiles, ", ")),
		})
	}

	for _, svc := range cfg.Services {
		s := Service{
			Name:       svc.Name,
			Image:      svc.Image,
			Command:    svc.Command,
			Entrypoint: svc.Entrypoint,
			User:       svc.User,
			WorkingDir: svc.WorkingDir,
			Hostname:   svc.Hostname,
			Restart:    svc.Restart,
			CapAdd:     svc.CapAdd,
			CapDrop:    svc.CapDrop,
			DNS:        svc.DNS,
			GroupAdd:   svc.GroupAdd,
			ReadOnly:   svc.ReadOnly,
			Privileged: svc.Privileged,
			StopSignal: svc.StopSignal,
			Labels:     svc.Labels,
			Sysctls:    svc.Sysctls,
		}

		for _, k := range sortedKeys(svc.Environment) {
			v := svc.Environment[k]
			ev := EnvVar{Name: k}
			if v != nil {
				ev.Value = *v
			}
			s.Environment = append(s.Environment, ev)
		}

		for _, v := range svc.Volumes {
			m := Mount{Type: string(v.Type), Source: v.Source, Target: v.Target, ReadOnly: v.ReadOnly}
			if v.Bind != nil {
				m.SELinux = v.Bind.SELinux
			}
			s.Volumes = append(s.Volumes, m)
		}

		for _, port := range svc.Ports {
			s.Ports = append(s.Ports, Port{
				HostIP:    port.HostIP,
				Published: port.Published,
				Target:    int(port.Target),
				Protocol:  port.Protocol,
			})
		}

		for _, netName := range sortedNetworkKeys(svc.Networks) {
			s.Networks = append(s.Networks, netName)
		}

		for _, dep := range sortedKeys(svc.DependsOn) {
			s.DependsOn = append(s.DependsOn, Dependency{
				Service:   dep,
				Condition: svc.DependsOn[dep].Condition,
			})
		}

		if hc := svc.HealthCheck; hc != nil {
			s.HealthCheck = &HealthCheck{
				Test:     hc.Test,
				Disabled: hc.Disable,
			}
			if hc.Interval != nil {
				s.HealthCheck.Interval = hc.Interval.String()
			}
			if hc.Timeout != nil {
				s.HealthCheck.Timeout = hc.Timeout.String()
			}
			if hc.StartPeriod != nil {
				s.HealthCheck.StartPeriod = hc.StartPeriod.String()
			}
			if hc.Retries != nil {
				s.HealthCheck.Retries = int(*hc.Retries)
			}
		}

		for _, d := range svc.Devices {
			s.Devices = append(s.Devices, d.Source+":"+d.Target+":"+d.Permissions)
		}
		for _, t := range svc.Tmpfs {
			s.Tmpfs = append(s.Tmpfs, t)
		}
		if svc.ShmSize != 0 {
			s.ShmSize = strconv.FormatInt(int64(svc.ShmSize), 10)
		}

		p.Unsupported = append(p.Unsupported, unsupportedFor(svc)...)
		p.Services = append(p.Services, s)
	}

	for _, volName := range sortedKeys(cfg.Volumes) {
		v := cfg.Volumes[volName]
		p.Volumes = append(p.Volumes, Volume{
			Name:     volName,
			Driver:   v.Driver,
			Options:  v.DriverOpts,
			Labels:   v.Labels,
			External: bool(v.External),
		})
	}

	for _, netName := range sortedKeys(cfg.Networks) {
		n := cfg.Networks[netName]
		network := Network{
			Name:     netName,
			Driver:   n.Driver,
			Internal: n.Internal,
			Labels:   n.Labels,
			External: bool(n.External),
		}
		for _, pool := range n.Ipam.Config {
			if pool.Subnet != "" {
				network.Subnets = append(network.Subnets, pool.Subnet)
			}
			if pool.Gateway != "" && network.Gateway == "" {
				network.Gateway = pool.Gateway
			}
		}
		p.Networks = append(p.Networks, network)
	}

	sort.Slice(p.Services, func(i, j int) bool { return p.Services[i].Name < p.Services[j].Name })
	return p
}

// unsupportedFor reports compose features with no faithful Quadlet
// translation. Being explicit is the point: the spec's non-goal is a partial
// port, not a silent one.
func unsupportedFor(svc types.ServiceConfig) []Unsupported {
	var out []Unsupported
	add := func(key, reason string) {
		out = append(out, Unsupported{Service: svc.Name, Key: key, Reason: reason})
	}

	if svc.Build != nil {
		add("build", "Quadlet builds images with a separate .build unit, which is outside "+
			"this version's scope. Build the image yourself and reference it by name, or "+
			"write the .build unit by hand.")
	}
	if len(svc.Profiles) > 0 {
		add("profiles", "systemd has no equivalent of a compose profile. The unit is "+
			"generated unconditionally; control it by enabling or masking the unit, or "+
			"by keeping profile variants in separate directories.")
	}
	if svc.Extends != nil {
		add("extends", "extends is resolved by the compose loader before conversion, so "+
			"the generated unit is already flattened. Nothing is lost, but the unit will "+
			"not resemble the compose file line for line.")
	}
	if svc.Deploy != nil {
		if svc.Deploy.Replicas != nil && *svc.Deploy.Replicas > 1 {
			add("deploy.replicas", "A Quadlet unit runs one container. For several "+
				"replicas use a systemd template unit, or generate one unit per replica.")
		}
		if svc.Deploy.Mode != "" && svc.Deploy.Mode != "replicated" {
			add("deploy.mode", "Swarm deployment modes have no Quadlet equivalent.")
		}
	}
	if svc.Scale != nil && *svc.Scale > 1 {
		add("scale", "A Quadlet unit runs one container. For several replicas use a "+
			"systemd template unit.")
	}
	if len(svc.Configs) > 0 {
		add("configs", "Swarm configs have no direct Quadlet equivalent. Use a bind "+
			"mount, or a Podman secret with type=mount.")
	}
	if len(svc.Secrets) > 0 {
		add("secrets", "Compose secrets are files under /run/secrets. Podman secrets are "+
			"equivalent but must be created separately with `podman secret create`, then "+
			"referenced with Secret=.")
	}
	if svc.NetworkMode != "" && svc.NetworkMode != "bridge" && svc.NetworkMode != "none" &&
		svc.NetworkMode != "host" && !strings.HasPrefix(svc.NetworkMode, "service:") &&
		!strings.HasPrefix(svc.NetworkMode, "container:") {
		add("network_mode", "This network mode has no direct Quadlet equivalent; check "+
			"the generated Network= value.")
	}
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func sortedNetworkKeys(m map[string]*types.ServiceNetworkConfig) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// sanitiseName makes a string usable as a systemd unit name.
func sanitiseName(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	out := strings.Trim(b.String(), "-_")
	if out == "" {
		out = "compose"
	}
	return out
}

// PublishedPort renders a port for `PublishPort=`.
func (p Port) PublishedPort() string {
	var b strings.Builder
	if p.HostIP != "" {
		b.WriteString(p.HostIP)
		b.WriteByte(':')
	}
	if p.Published != "" {
		b.WriteString(p.Published)
		b.WriteByte(':')
	}
	b.WriteString(strconv.Itoa(p.Target))
	if p.Protocol != "" && p.Protocol != "tcp" {
		b.WriteByte('/')
		b.WriteString(p.Protocol)
	}
	return b.String()
}
