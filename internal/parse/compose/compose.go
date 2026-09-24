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
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

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
	// NetworkMode is compose's `network_mode`, empty when the service joins
	// Networks instead.
	NetworkMode string
	Networks    []ServiceNetwork
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
	// ContainerName is compose's `container_name`, empty when unset.
	ContainerName string
	// ExtraHosts are `host:ip` mappings, sorted by host.
	ExtraHosts []string
	// Init is compose's `init`, nil when unset.
	Init   *bool
	UserNS string
	// StopTimeout is `stop_grace_period` in whole seconds, rounded up; nil
	// when unset.
	StopTimeout *int
	DNSSearch   []string
	// Ulimits are `name=soft[:hard]` values, sorted by name.
	Ulimits []string
	// Memory is `mem_limit` in bytes, empty when unset.
	Memory string
	// Pull is the Podman pull policy compose's `pull_policy` maps to, empty
	// when unset or when it has no Podman equivalent.
	Pull        string
	LogDriver   string
	LogOptions  map[string]string
	Annotations map[string]string
	PidsLimit   string
	// PID and IPC are compose's `pid` and `ipc` namespace modes.
	PID string
	IPC string
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
	// Propagation is a bind's `propagation`, e.g. `rshared`.
	Propagation string
	// NoCopy is a volume's `nocopy`.
	NoCopy bool
	// TmpfsSize and TmpfsMode are a tmpfs mount's `size` in bytes and `mode`,
	// zero when unset.
	TmpfsSize int64
	TmpfsMode uint32
}

// ServiceNetwork is one entry of a service's `networks:`, naming a declared
// network by its compose key.
type ServiceNetwork struct {
	Name        string
	Aliases     []string
	IPv4Address string
	IPv6Address string
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
	// Required is false when compose may start the service without it.
	Required bool
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
	// Name is the compose key. ObjectName is the Podman volume name: compose's
	// `name:` when set, otherwise the key.
	Name       string
	ObjectName string
	Driver     string
	Options    map[string]string
	Labels     map[string]string
	External   bool
}

// Network is a declared network.
type Network struct {
	// Name is the compose key. ObjectName is the Podman network name: compose's
	// `name:` when set, otherwise `<project>_<key>` as compose itself names it.
	Name       string
	ObjectName string
	Driver     string
	Internal   bool
	Labels     map[string]string
	External   bool
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
	for _, svcName := range sortedKeys(cfg.DisabledServices) {
		svc := cfg.DisabledServices[svcName]
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

	for _, svcName := range sortedKeys(cfg.Services) {
		svc := cfg.Services[svcName]
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

			ContainerName: svc.ContainerName,
			Init:          svc.Init,
			UserNS:        svc.UserNSMode,
			DNSSearch:     svc.DNSSearch,
			Pull:          pullPolicy(svc.PullPolicy),
			Annotations:   svc.Annotations,
			PID:           svc.Pid,
			IPC:           svc.Ipc,
		}

		for _, host := range sortedKeys(svc.ExtraHosts) {
			for _, ip := range svc.ExtraHosts[host] {
				s.ExtraHosts = append(s.ExtraHosts, host+":"+ip)
			}
		}
		if svc.StopGracePeriod != nil {
			seconds := int(math.Ceil(time.Duration(*svc.StopGracePeriod).Seconds()))
			s.StopTimeout = &seconds
		}
		for _, name := range sortedKeys(svc.Ulimits) {
			l := svc.Ulimits[name]
			if l.Single != 0 {
				s.Ulimits = append(s.Ulimits, fmt.Sprintf("%s=%d", name, l.Single))
			} else {
				s.Ulimits = append(s.Ulimits, fmt.Sprintf("%s=%d:%d", name, l.Soft, l.Hard))
			}
		}
		if svc.MemLimit != 0 {
			s.Memory = strconv.FormatInt(int64(svc.MemLimit), 10)
		}
		if svc.PidsLimit != 0 {
			s.PidsLimit = strconv.FormatInt(svc.PidsLimit, 10)
		}
		if svc.Logging != nil {
			s.LogDriver = svc.Logging.Driver
			s.LogOptions = svc.Logging.Options
		}

		for _, k := range sortedKeys(svc.Environment) {
			// A nil value is a bare `- VAR` that the environment did not
			// resolve; compose leaves it unset, and unsupportedFor reports it.
			if v := svc.Environment[k]; v != nil {
				s.Environment = append(s.Environment, EnvVar{Name: k, Value: *v})
			}
		}

		for _, v := range svc.Volumes {
			m := Mount{Type: string(v.Type), Source: v.Source, Target: v.Target, ReadOnly: v.ReadOnly}
			if v.Bind != nil {
				m.SELinux = v.Bind.SELinux
				m.Propagation = v.Bind.Propagation
			}
			if v.Volume != nil {
				m.NoCopy = v.Volume.NoCopy
			}
			if v.Tmpfs != nil {
				m.TmpfsSize = int64(v.Tmpfs.Size)
				m.TmpfsMode = v.Tmpfs.Mode
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

		s.NetworkMode = svc.NetworkMode
		for _, netName := range sortedKeys(svc.Networks) {
			sn := ServiceNetwork{Name: netName}
			if cfg := svc.Networks[netName]; cfg != nil {
				sn.Aliases = cfg.Aliases
				sn.IPv4Address = cfg.Ipv4Address
				sn.IPv6Address = cfg.Ipv6Address
			}
			s.Networks = append(s.Networks, sn)
		}

		for _, dep := range sortedKeys(svc.DependsOn) {
			s.DependsOn = append(s.DependsOn, Dependency{
				Service:   dep,
				Condition: svc.DependsOn[dep].Condition,
				Required:  svc.DependsOn[dep].Required,
			})
		}

		if hc := svc.HealthCheck; hc != nil {
			s.HealthCheck = &HealthCheck{
				Test: hc.Test,
				// `test: ["NONE"]` disables the image's healthcheck just as
				// `disable: true` does.
				Disabled: hc.Disable || (len(hc.Test) > 0 && hc.Test[0] == "NONE"),
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
		// The loader fills in `<project>_<key>` when no `name:` is given.
		// That default is not taken: VolumeName= has always been the bare
		// key, and renaming a volume would strand the data already in it.
		objectName := v.Name
		if !v.External && v.Name == name+"_"+volName {
			objectName = volName
		}
		p.Volumes = append(p.Volumes, Volume{
			Name:       volName,
			ObjectName: objectName,
			Driver:     v.Driver,
			Options:    v.DriverOpts,
			Labels:     v.Labels,
			External:   bool(v.External),
		})
	}

	for _, netName := range sortedKeys(cfg.Networks) {
		n := cfg.Networks[netName]
		network := Network{
			Name:       netName,
			ObjectName: n.Name,
			Driver:     n.Driver,
			Internal:   n.Internal,
			Labels:     n.Labels,
			External:   bool(n.External),
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
	for _, k := range sortedKeys(svc.Environment) {
		if svc.Environment[k] == nil {
			add("environment", fmt.Sprintf("%s has no value and was not set in the environment "+
				"quaddoc ran in, so compose would leave it unset. No Environment= line was "+
				"written; add Environment=%s=VALUE or an EnvironmentFile= if the container "+
				"needs it.", k, k))
		}
	}
	// Only the host namespaces go through PodmanArgs=: the other modes name
	// compose services or containers, which Podman knows by other names.
	if svc.Pid != "" && svc.Pid != "host" {
		add("pid", fmt.Sprintf("Quadlet has no key for the PID namespace, and `pid: %s` has "+
			"no exact Podman equivalent here. Add PodmanArgs=--pid=... by hand, naming the "+
			"container as Podman knows it (podman-run(1), --pid).", svc.Pid))
	}
	if svc.Ipc != "" && svc.Ipc != "host" {
		add("ipc", fmt.Sprintf("Quadlet has no key for the IPC namespace, and `ipc: %s` has "+
			"no exact Podman equivalent here. Add PodmanArgs=--ipc=... by hand if the "+
			"container needs it (podman-run(1), --ipc).", svc.Ipc))
	}
	if len(svc.SecurityOpt) > 0 {
		add("security_opt", fmt.Sprintf("%s was not translated. Quadlet has dedicated keys "+
			"for the common options: label=disable is SecurityLabelDisable=true, "+
			"no-new-privileges is NoNewPrivileges=true, seccomp=PROFILE is "+
			"SeccompProfile=PROFILE, apparmor=PROFILE is AppArmor=PROFILE "+
			"(podman-systemd.unit(5)). Add the ones you need.", strings.Join(svc.SecurityOpt, ", ")))
	}
	if svc.CgroupParent != "" {
		add("cgroup_parent", fmt.Sprintf("systemd owns the cgroup of a Quadlet container. To "+
			"place it under %s, set Slice= in the [Service] section instead.", svc.CgroupParent))
	}
	if svc.PullPolicy != "" && pullPolicy(svc.PullPolicy) == "" {
		add("pull_policy", fmt.Sprintf("`pull_policy: %s` has no Podman equivalent; Podman "+
			"pulls always, missing, never, or newer (podman-run(1), --pull). Set Pull= to "+
			"the closest, or refresh the image with a timer running `podman pull`.", svc.PullPolicy))
	}
	if hc := svc.HealthCheck; hc != nil && hc.StartInterval != nil {
		add("healthcheck.start_interval", "Podman has no interval that applies only during "+
			"the start period: HealthInterval= applies throughout, and HealthStartupCmd= "+
			"with HealthStartupInterval= runs a separate startup check "+
			"(podman-systemd.unit(5)). Choose one of those if the faster polling at start-up "+
			"matters.")
	}
	return out
}

// pullPolicy maps a compose pull_policy onto Podman's --pull, or returns ""
// when Podman has no equivalent.
func pullPolicy(policy string) string {
	switch policy {
	case "always", "never", "missing":
		return policy
	case "if_not_present":
		return "missing"
	}
	return ""
}

func sortedKeys[V any](m map[string]V) []string {
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
