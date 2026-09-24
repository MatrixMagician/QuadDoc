// Package generate turns a compose project into Quadlet units.
//
// Two commitments shape the output. First, every non-obvious translation
// decision is annotated in the unit itself, because the person reading the unit
// in six months is the one who needs to know why it says what it says. Second,
// nothing is dropped silently: a compose feature that cannot be translated
// becomes a finding, never an omission.
//
// The default shape is one .container per service plus a .network per compose
// network, per ADR-0001. That is not a stylistic choice: Podman's default
// network has DNS disabled, so without a user-defined network, sibling service
// names do not resolve and the compose semantics are lost.
package generate

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/MatrixMagician/quaddoc/internal/parse/compose"
)

// Options control conversion.
type Options struct {
	// Pod emits a single .pod unit that every container joins, instead of a
	// shared .network. Containers in a pod share a network namespace and
	// reach each other on localhost.
	Pod bool
	// Annotate writes explanatory comments into the generated units.
	// On by default; tests that compare exact bytes may turn it off.
	Annotate bool
}

// Unit is a generated unit file.
type Unit struct {
	// Name is the file name, e.g. `web.container`.
	Name string
	// Content is the file's text.
	Content string
}

// Result is everything a conversion produced.
type Result struct {
	Units []Unit
	// Notes are translation decisions worth reporting to the user, beyond
	// what is annotated in the files.
	Notes []Note
}

// Note is a translation decision or an untranslatable feature.
type Note struct {
	// Unit is the generated unit it concerns, empty for project-wide notes.
	Unit string
	// Message states what happened.
	Message string
	// Severity is `error`, `warning`, or `note`.
	Severity string
}

// builder accumulates a unit file's text.
type builder struct {
	annotate bool
	b        strings.Builder
	section  string
}

func (u *builder) comment(format string, args ...any) {
	if !u.annotate {
		return
	}
	for _, line := range wrap(fmt.Sprintf(format, args...), 74) {
		if line == "" {
			// A bare "#" rather than "# ", so the file carries no trailing
			// whitespace.
			u.b.WriteString("#\n")
			continue
		}
		fmt.Fprintf(&u.b, "# %s\n", line)
	}
}

func (u *builder) sectionHeader(name string) {
	if u.b.Len() > 0 {
		u.b.WriteByte('\n')
	}
	fmt.Fprintf(&u.b, "[%s]\n", name)
	u.section = name
}

func (u *builder) key(key, value string) {
	if value == "" {
		return
	}
	// systemd expands specifiers and variables in the podman command line
	// Quadlet builds from these values, and Quadlet deliberately passes them
	// through, so a literal `%` or `$` must be doubled here. See the
	// "Specifiers" section of systemd.unit(5) and "Command lines" in
	// systemd.service(5); verified against Podman 5.8.4.
	value = strings.NewReplacer("%", "%%", "$", "$$").Replace(value)
	fmt.Fprintf(&u.b, "%s=%s\n", key, value)
}

func (u *builder) keys(key string, values []string) {
	for _, v := range values {
		u.key(key, v)
	}
}

func (u *builder) String() string { return u.b.String() }

// quote renders one word in systemd's command-line syntax, which Quadlet uses
// to split Exec=, PodmanArgs=, and the values of Environment=, Label=,
// Annotation=, LogOpt= and Sysctl= (podman-systemd.unit(5)). Plain words stay
// bare, for readability.
func quote(word string) string {
	if word != "" && !strings.ContainsAny(word, " \t\r\n\"'\\") {
		return word
	}
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`, "\r", `\r`).Replace(word) + `"`
}

// quoteAll quotes each word and joins them into one command line.
func quoteAll(words []string) string {
	quoted := make([]string, len(words))
	for i, w := range words {
		quoted[i] = quote(w)
	}
	return strings.Join(quoted, " ")
}

// pair renders a `key=value` assignment with the value quoted, the form
// Environment=, Label=, Annotation=, LogOpt= and Sysctl= split on. Quoting the
// value alone, not the whole pair, keeps the key readable to quaddoc's own unit
// parser too.
func pair(key, value string) string {
	return key + "=" + quote(value)
}

// jsonArray renders words as a JSON array, the form Podman takes for a
// multi-word --entrypoint and for an exec-form --health-cmd. Quadlet passes
// both values through without splitting them.
func jsonArray(words []string) string {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	// Without this, & is written as \u0026; Podman decodes either, but a human reads &&.
	enc.SetEscapeHTML(false)
	_ = enc.Encode(words) // a []string always encodes
	return strings.TrimSuffix(b.String(), "\n")
}

// wrap breaks a comment into lines of at most width characters, so annotations
// stay readable in a terminal.
func wrap(s string, width int) []string {
	words := strings.Fields(s)
	if len(words) == 0 {
		return []string{""}
	}

	var lines []string
	current := words[0]
	for _, w := range words[1:] {
		if len(current)+1+len(w) > width {
			lines = append(lines, current)
			current = w
			continue
		}
		current += " " + w
	}
	return append(lines, current)
}

// Convert turns a compose project into Quadlet units.
func Convert(p *compose.Project, opts Options) *Result {
	result := &Result{}

	// Untranslatable compose features are reported before anything else, so
	// the user sees them even if generation then fails.
	for _, un := range p.Unsupported {
		unit := ""
		if un.Service != "" {
			unit = un.Service + ".container"
		}
		result.Notes = append(result.Notes, Note{
			Unit:     unit,
			Severity: "warning",
			Message:  fmt.Sprintf("compose key %q is not translated: %s", un.Key, un.Reason),
		})
	}

	if opts.Pod {
		result.Units = append(result.Units, generatePod(p, opts))
	} else {
		for _, n := range p.Networks {
			if n.External {
				result.Notes = append(result.Notes, Note{
					Severity: "note",
					Message: fmt.Sprintf("network %q is external, so no .network unit was generated; "+
						"create it yourself with `podman network create %s`", n.Name, n.ObjectName),
				})
				continue
			}
			result.Units = append(result.Units, generateNetwork(p, n, opts))
		}
	}

	for _, v := range p.Volumes {
		if v.External {
			result.Notes = append(result.Notes, Note{
				Severity: "note",
				Message: fmt.Sprintf("volume %q is external, so no .volume unit was generated; "+
					"create it yourself with `podman volume create %s`", v.Name, v.ObjectName),
			})
			continue
		}
		result.Units = append(result.Units, generateVolume(v, opts))
	}

	for _, s := range p.Services {
		unit, notes := generateContainer(p, s, opts)
		result.Units = append(result.Units, unit)
		result.Notes = append(result.Notes, notes...)
	}

	sort.Slice(result.Units, func(i, j int) bool { return result.Units[i].Name < result.Units[j].Name })
	return result
}

// networkUnit names the .network unit generated for a compose network. The
// project prefix keeps networks of different projects apart in the shared
// Quadlet search path.
func networkUnit(p *compose.Project, key string) string {
	return p.Name + "-" + key
}

func generateNetwork(p *compose.Project, n compose.Network, opts Options) Unit {
	var u builder
	u.annotate = opts.Annotate

	u.comment("Generated by quaddoc from compose network %q.", n.Name)
	u.comment("")
	u.comment("Compose gives every service a DNS name that its siblings can resolve. " +
		"Podman's default network has DNS disabled, so a user-defined network like " +
		"this one is required to preserve that behaviour, not merely a tidier way " +
		"to arrange things.")
	u.comment("")
	u.comment("NetworkName= makes Podman name the network `%s`, the name compose "+
		"gives it, rather than Quadlet's default of `systemd-%s`.", n.ObjectName, networkUnit(p, n.Name))

	u.sectionHeader("Network")
	u.key("NetworkName", n.ObjectName)
	if n.Driver != "" && n.Driver != "bridge" {
		u.key("Driver", n.Driver)
	}
	if n.Internal {
		u.key("Internal", "true")
	}
	u.keys("Subnet", n.Subnets)
	u.key("Gateway", n.Gateway)

	u.sectionHeader("Install")
	u.key("WantedBy", "default.target")

	return Unit{Name: networkUnit(p, n.Name) + ".network", Content: u.String()}
}

func generatePod(p *compose.Project, opts Options) Unit {
	var u builder
	u.annotate = opts.Annotate

	u.comment("Generated by quaddoc from a compose project.")
	u.comment("")
	u.comment("Containers in a pod share a network namespace, so they reach each " +
		"other on localhost rather than by service name. Where the compose file " +
		"relied on service-name DNS, those references need changing to localhost.")

	u.sectionHeader("Pod")
	u.key("PodName", p.Name)

	for _, s := range p.Services {
		for _, port := range s.Ports {
			// In a pod, ports are published by the pod, not by its members.
			u.key("PublishPort", port.PublishedPort())
		}
	}

	u.sectionHeader("Install")
	u.key("WantedBy", "default.target")

	return Unit{Name: p.Name + ".pod", Content: u.String()}
}

func generateVolume(v compose.Volume, opts Options) Unit {
	var u builder
	u.annotate = opts.Annotate

	u.comment("Generated by quaddoc from a compose project.")
	u.comment("")
	u.comment("VolumeName= makes Podman name the volume `%s`, rather than Quadlet's "+
		"default of `systemd-%s`. Reference it from a container as `%s.volume`, not "+
		"by the bare name.", v.ObjectName, v.Name, v.Name)

	u.sectionHeader("Volume")
	u.key("VolumeName", v.ObjectName)
	u.key("Driver", v.Driver)

	for _, k := range sortedKeys(v.Options) {
		// Quadlet expresses local-driver bind options as its own keys rather
		// than passing them through verbatim.
		switch k {
		case "type":
			u.key("Type", v.Options[k])
		case "device":
			u.key("Device", v.Options[k])
		case "o":
			u.key("Options", v.Options[k])
		default:
			u.key("PodmanArgs", "--opt "+quote(k+"="+v.Options[k]))
		}
	}
	for _, k := range sortedKeys(v.Labels) {
		u.key("Label", pair(k, v.Labels[k]))
	}

	return Unit{Name: v.Name + ".volume", Content: u.String()}
}

func generateContainer(p *compose.Project, s compose.Service, opts Options) (Unit, []Note) {
	var u builder
	var notes []Note
	u.annotate = opts.Annotate

	u.comment("Generated by quaddoc from compose service %q.", s.Name)

	u.sectionHeader("Unit")
	u.key("Description", fmt.Sprintf("%s (from compose service %s)", s.Name, s.Name))

	// depends_on becomes systemd ordering, which is weaker than what compose
	// promises. Say so rather than let the difference be discovered in
	// production.
	for _, dep := range s.DependsOn {
		target := dep.Service + ".service"
		switch dep.Condition {
		case "service_healthy":
			u.comment("")
			u.comment("compose had `depends_on: %s: condition: service_healthy`. systemd "+
				"orders units but does not gate on health, so After= alone starts this "+
				"container as soon as %s has *started*, not once it is healthy. To close "+
				"the gap, set Notify=healthy on %s.container together with a healthcheck: "+
				"its service then reports started only once Podman marks it healthy.",
				dep.Service, dep.Service, dep.Service)
			notes = append(notes, Note{
				Unit:     s.Name + ".container",
				Severity: "warning",
				Message: fmt.Sprintf("depends_on %s used condition: service_healthy, which systemd "+
					"ordering cannot express; see the comment in the generated unit", dep.Service),
			})
		case "service_completed_successfully":
			u.comment("")
			u.comment("compose had `depends_on: %s: condition: "+
				"service_completed_successfully`. That maps to After= plus a Requires= on "+
				"a unit that runs to completion; check that %s.container is a one-shot.",
				dep.Service, dep.Service)
		}
		u.key("After", target)
		if dep.Required {
			u.key("Requires", target)
		} else {
			// compose's `required: false` starts this service even when the
			// dependency fails, which is what Wants= means (systemd.unit(5)).
			u.key("Wants", target)
		}
	}

	u.sectionHeader("Container")
	containerName := s.Name
	if s.ContainerName != "" {
		containerName = s.ContainerName
	}
	u.key("ContainerName", containerName)
	u.key("Image", s.Image)
	u.key("Pull", s.Pull)

	switch {
	case len(s.Entrypoint) == 1 && quote(s.Entrypoint[0]) == s.Entrypoint[0]:
		u.key("Entrypoint", s.Entrypoint[0])
	case len(s.Entrypoint) > 0:
		// Quadlet hands Entrypoint= to --entrypoint unsplit, so anything
		// beyond one plain word needs Podman's JSON form.
		u.key("Entrypoint", jsonArray(s.Entrypoint))
	}
	if len(s.Command) > 0 {
		// Quadlet's Exec= is the command, matching compose's `command:`.
		u.key("Exec", quoteAll(s.Command))
	}

	if s.User != "" {
		user, group, hasGroup := strings.Cut(s.User, ":")
		u.key("User", user)
		if hasGroup {
			u.key("Group", group)
		}
	}

	u.key("WorkingDir", s.WorkingDir)
	u.key("HostName", s.Hostname)

	for _, env := range s.Environment {
		u.key("Environment", pair(env.Name, env.Value))
	}

	for _, m := range s.Volumes {
		if m.Type == "tmpfs" {
			// Volume= with a bare target would make a persistent anonymous
			// volume, not a tmpfs.
			u.key("Tmpfs", renderTmpfs(m))
			continue
		}
		value, note := renderMount(p, s, m)
		if note != "" {
			u.comment("")
			u.comment("%s", note)
		}
		u.key("Volume", value)
	}

	if !opts.Pod {
		for _, port := range s.Ports {
			u.key("PublishPort", port.PublishedPort())
		}
		switch mode := s.NetworkMode; {
		case mode == "":
			if containerName != s.Name {
				u.comment("")
				u.comment("compose also resolves this container by its service name, %s, "+
					"so each network gives it that alias.", s.Name)
			}
			for _, sn := range s.Networks {
				if containerName != s.Name {
					sn.Aliases = append([]string{s.Name}, sn.Aliases...)
				}
				u.key("Network", networkRef(p, sn))
			}
		case strings.HasPrefix(mode, "service:"):
			sibling := strings.TrimPrefix(mode, "service:")
			u.comment("")
			u.comment("compose had `network_mode: %s`, so this container shares %s's network "+
				"stack rather than joining a network. Network=%s.container does the same, "+
				"and Quadlet starts this unit after %s's.", mode, sibling, sibling, sibling)
			u.key("Network", sibling+".container")
		default:
			// host, none, bridge, container:NAME and the rest are all values
			// podman's --network takes as they are (podman-run(1)).
			u.comment("")
			u.comment("compose had `network_mode: %s`, which Podman takes as it is, so this "+
				"container joins none of the project's networks.", mode)
			u.key("Network", mode)
		}
	} else {
		u.comment("")
		u.comment("Ports are published by the pod, not by its members.")
		u.key("Pod", p.Name+".pod")
	}

	u.keys("AddCapability", s.CapAdd)
	u.keys("DropCapability", s.CapDrop)
	u.keys("AddDevice", s.Devices)
	u.keys("DNS", s.DNS)
	u.keys("DNSSearch", s.DNSSearch)
	u.keys("AddHost", s.ExtraHosts)
	u.keys("GroupAdd", s.GroupAdd)
	u.keys("Tmpfs", s.Tmpfs)
	if s.Init != nil {
		u.key("RunInit", strconv.FormatBool(*s.Init))
	}
	u.key("UserNS", s.UserNS)
	u.keys("Ulimit", s.Ulimits)
	u.key("Memory", s.Memory)
	u.key("PidsLimit", s.PidsLimit)
	u.key("LogDriver", s.LogDriver)
	for _, k := range sortedKeys(s.LogOptions) {
		// Quadlet splits LogOpt= on whitespace, as it does Environment=.
		u.key("LogOpt", pair(k, s.LogOptions[k]))
	}
	for _, k := range sortedKeys(s.Annotations) {
		u.key("Annotation", pair(k, s.Annotations[k]))
	}
	// Quadlet has no key for these namespaces. The host modes mean the same
	// to podman run as to compose (podman-run(1), --pid and --ipc); the rest
	// are reported by the compose loader.
	if s.PID == "host" {
		u.key("PodmanArgs", "--pid=host")
	}
	if s.IPC == "host" {
		u.key("PodmanArgs", "--ipc=host")
	}

	if s.ReadOnly {
		u.key("ReadOnly", "true")
	}
	if s.Privileged {
		u.comment("")
		u.comment("compose set `privileged: true`. This disables most container isolation; " +
			"consider whether specific AddCapability= or AddDevice= entries would do.")
		u.key("PodmanArgs", "--privileged")
		notes = append(notes, Note{
			Unit:     s.Name + ".container",
			Severity: "warning",
			Message:  "service runs privileged, which disables most container isolation",
		})
	}
	u.key("StopSignal", s.StopSignal)
	if s.StopTimeout != nil {
		u.key("StopTimeout", strconv.Itoa(*s.StopTimeout))
		// podman-systemd.unit(5): StopTimeout= "should be lower than the actual
		// systemd unit timeout", and systemd's default TimeoutStopSec= is 90s.
		if *s.StopTimeout >= 90 {
			note := fmt.Sprintf("compose set `stop_grace_period` to %ds, which is not below "+
				"systemd's default stop timeout of 90s, so systemd may kill the container "+
				"before the grace period ends. Add TimeoutStopSec=%d or more to the [Service] "+
				"section.", *s.StopTimeout, *s.StopTimeout+30)
			u.comment("")
			u.comment("%s", note)
			notes = append(notes, Note{Unit: s.Name + ".container", Severity: "note", Message: note})
		}
	}
	if s.ShmSize != "" {
		u.key("ShmSize", s.ShmSize)
	}
	for _, k := range sortedKeys(s.Sysctls) {
		u.key("Sysctl", pair(k, s.Sysctls[k]))
	}
	for _, k := range sortedKeys(s.Labels) {
		u.key("Label", pair(k, s.Labels[k]))
	}

	if hc := s.HealthCheck; hc != nil && !hc.Disabled {
		cmd := healthCommand(hc.Test)
		if cmd != "" {
			u.key("HealthCmd", cmd)
			u.key("HealthInterval", hc.Interval)
			u.key("HealthTimeout", hc.Timeout)
			u.key("HealthStartPeriod", hc.StartPeriod)
			if hc.Retries > 0 {
				u.key("HealthRetries", fmt.Sprintf("%d", hc.Retries))
			}
		}
	} else if hc != nil && hc.Disabled {
		u.comment("")
		u.comment("compose disabled the healthcheck, so the image's own HEALTHCHECK is disabled too.")
		u.key("HealthCmd", "none")
	}

	u.sectionHeader("Service")
	restart, note := renderRestart(s.Restart)
	if note != "" {
		// The comment belongs above the key, so rebuild the section.
		u.comment("")
		u.comment("%s", note)
		notes = append(notes, Note{
			Unit:     s.Name + ".container",
			Severity: "note",
			Message:  note,
		})
	}
	u.key("Restart", restart)

	u.sectionHeader("Install")
	u.key("WantedBy", "default.target")

	return Unit{Name: s.Name + ".container", Content: u.String()}, notes
}

// networkRef renders a service's place on a compose network as a Network=
// value: the generated .network unit, or the real name of an external network,
// followed by the per-network ip=, ip6= and alias= options podman's --network
// takes (podman-run(1)). Quadlet keeps those options when it resolves the unit
// reference, verified against Podman 5.8.4.
func networkRef(p *compose.Project, sn compose.ServiceNetwork) string {
	ref := networkUnit(p, sn.Name) + ".network"
	for _, n := range p.Networks {
		if n.Name == sn.Name && n.External {
			ref = n.ObjectName
		}
	}

	var options []string
	if sn.IPv4Address != "" {
		options = append(options, "ip="+sn.IPv4Address)
	}
	if sn.IPv6Address != "" {
		options = append(options, "ip6="+sn.IPv6Address)
	}
	for _, alias := range sn.Aliases {
		options = append(options, "alias="+alias)
	}
	if len(options) > 0 {
		ref += ":" + strings.Join(options, ",")
	}
	return ref
}

// renderTmpfs renders a long-syntax tmpfs mount as a `Tmpfs=` value, in the
// CONTAINER-DIR[:OPTIONS] form podman's --tmpfs takes (podman-run(1)).
func renderTmpfs(m compose.Mount) string {
	var options []string
	if m.ReadOnly {
		options = append(options, "ro")
	}
	if m.TmpfsSize != 0 {
		options = append(options, "size="+strconv.FormatInt(m.TmpfsSize, 10))
	}
	if m.TmpfsMode != 0 {
		options = append(options, "mode="+strconv.FormatUint(uint64(m.TmpfsMode), 8))
	}
	return join("", m.Target, options)
}

// renderMount turns a compose mount into a `Volume=` value, and returns an
// annotation when the translation was not obvious.
func renderMount(p *compose.Project, s compose.Service, m compose.Mount) (string, string) {
	var options []string
	if m.ReadOnly {
		options = append(options, "ro")
	}

	switch m.Type {
	case "volume":
		// A named volume declared in the compose file becomes a `.volume`
		// unit reference, so the generated units carry the dependency.
		source := m.Source
		note := ""
		if v, ok := declaredVolume(p, m.Source); ok && v.External {
			source = v.ObjectName
		} else if ok {
			source = m.Source + ".volume"
			note = fmt.Sprintf("Named volume %q refers to the %s.volume unit, which Podman "+
				"materialises as a volume called `%s`. The .volume suffix is what "+
				"creates the dependency between the two units.", m.Source, m.Source, v.ObjectName)
		}
		if m.SELinux != "" {
			options = append(options, m.SELinux)
		}
		if m.NoCopy {
			options = append(options, "nocopy")
		}
		return join(source, m.Target, options), note

	default: // bind
		if m.Propagation != "" {
			options = append(options, m.Propagation)
		}
		if m.SELinux != "" {
			options = append(options, m.SELinux)
			return join(m.Source, m.Target, options), ""
		}
		// Deliberately not guessing at a label here: whether the mount wants
		// `:z` or `:Z` depends on whether other units share the source, which
		// is a project-wide question the rule engine answers. QD001 reports
		// it, and `quaddoc fix` applies it.
		return join(m.Source, m.Target, options),
			fmt.Sprintf("Bind mount of %s. On an SELinux system this needs a relabelling "+
				"option, `:Z` for a source used by this container alone or `:z` for one "+
				"shared with others. quaddoc does not guess: run `quaddoc lint` to see "+
				"which applies, and `quaddoc fix` to apply it.", m.Source)
	}
}

// declaredVolume finds a named volume declared at the top level of the compose
// file. One that is not external has a generated `.volume` unit.
func declaredVolume(p *compose.Project, name string) (compose.Volume, bool) {
	for _, v := range p.Volumes {
		if v.Name == name {
			return v, true
		}
	}
	return compose.Volume{}, false
}

func join(source, target string, options []string) string {
	var parts []string
	if source != "" {
		parts = append(parts, source)
	}
	parts = append(parts, target)
	value := strings.Join(parts, ":")
	if len(options) > 0 {
		value += ":" + strings.Join(options, ",")
	}
	return value
}

// renderRestart maps a compose restart policy onto systemd's, and explains the
// one that has no exact equivalent.
func renderRestart(policy string) (string, string) {
	switch policy {
	case "", "no":
		return "no", ""
	case "always":
		return "always", ""
	case "on-failure":
		return "on-failure", ""
	case "unless-stopped":
		// systemd has no policy that means "restart unless a human stopped
		// it". Restart=always is the closest, and differs only in that a
		// manual `systemctl stop` is respected until the next boot, whereas
		// compose would leave the container stopped across a daemon restart.
		return "always", "compose used `restart: unless-stopped`, which systemd cannot " +
			"express exactly. Restart=always is the closest: systemd honours an explicit " +
			"`systemctl stop` for as long as the machine stays up, and starts the unit " +
			"again at boot because of the [Install] section."
	default:
		if retries, ok := strings.CutPrefix(policy, "on-failure:"); ok {
			return "on-failure", fmt.Sprintf("compose used `restart: %s`, which gives up after %s "+
				"retries. Restart=on-failure has no retry count: systemd limits restarts by "+
				"rate instead, so set StartLimitBurst= and StartLimitIntervalSec= in [Unit] "+
				"if the cap matters.", policy, retries)
		}
		return "always", fmt.Sprintf("compose restart policy %q was not recognised; "+
			"Restart=always was used.", policy)
	}
}

// healthCommand renders a compose healthcheck test as a HealthCmd= value.
//
// compose's forms are `["CMD", "a", "b"]` for a direct exec, `["CMD-SHELL",
// "..."]` for a shell command, and `["NONE"]` to disable, which the compose
// loader turns into HealthCheck.Disabled before this is reached. Podman runs a
// plain --health-cmd string through a shell, so the exec form stays a JSON
// array: otherwise its arguments are re-split, and an image without a shell
// cannot run it at all (podman-run(1), --health-cmd).
func healthCommand(test []string) string {
	if len(test) == 0 {
		return ""
	}
	switch test[0] {
	case "CMD":
		return jsonArray(test)
	case "CMD-SHELL":
		return strings.Join(test[1:], " ")
	default:
		return strings.Join(test, " ")
	}
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
