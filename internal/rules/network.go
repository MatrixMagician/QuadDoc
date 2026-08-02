package rules

import (
	"fmt"
	"strings"

	"github.com/MatrixMagician/quaddoc/internal/ir"
)

// Networking, naming, and lifecycle rules.
func init() {
	Register(&Rule{
		ID:      "QD030",
		Summary: "Sibling containers cannot resolve each other without a shared network",
		Rationale: "Podman's default network has DNS disabled, so containers on it cannot " +
			"resolve each other by name at all. This is not a degraded form of compose's " +
			"behaviour, it is the absence of it: a container that expects to reach a " +
			"sibling by service name fails with an unresolvable host.",
		Citation: "Observed on Podman 5.8.4: `podman network inspect podman` reports " +
			"\"dns_enabled\": false for the default network. podman-network-create(1) " +
			"enables DNS for user-defined networks, which podman-systemd.unit(5) " +
			"creates from a .network unit.",
		DefaultSeverity: Error,
		Fixable:         true,
		Check:           checkQD030,
	})

	Register(&Rule{
		ID:      "QD031",
		Summary: "Published port is below the unprivileged threshold",
		Rationale: "A rootless container cannot bind a host port below the kernel's " +
			"unprivileged threshold, so the unit fails to start with a permission error " +
			"that names the port but not the reason. The threshold is a sysctl, not a " +
			"constant, and administrators commonly lower it.",
		Citation: "net.ipv4.ip_unprivileged_port_start, documented in ip-sysctl.txt; " +
			"read from the live system under host context rather than assumed. " +
			"Observed as 1024 on the reference platform.",
		DefaultSeverity:  Warning,
		NeedsHostContext: true,
		Check:            checkQD031,
	})

	Register(&Rule{
		ID:      "QD032",
		Summary: "Unit name collides with an existing unit or Podman object",
		Rationale: "Quadlet prefixes the objects it creates with `systemd-`, so a name " +
			"collision is not always obvious from the unit file. Two units resolving to " +
			"the same object silently share it, and whichever starts last wins.",
		Citation: "podman-systemd.unit(5), Volume=: \"If SOURCE-VOLUME ends with " +
			".volume, a Podman named volume called systemd-$name is used\". The same " +
			"prefixing applies to networks. Verified on Podman 5.8.4: pg.volume created " +
			"a volume named systemd-pg.",
		DefaultSeverity:  Error,
		NeedsHostContext: true,
		Check:            checkQD032,
	})

	Register(&Rule{
		ID:      "QD020",
		Summary: "Ordering does not wait for a dependency to become healthy",
		Rationale: "systemd's After= orders one unit after another has *started*, which " +
			"for a container means the moment Podman launched it, not the moment the " +
			"process inside is ready to serve. A dependent container therefore starts " +
			"against a database that is still initialising. Notify=healthy closes the " +
			"gap by delaying the readiness notification until Podman marks the container " +
			"healthy.",
		Citation: "podman-systemd.unit(5), Notify=: \"setting Notify to healthy will " +
			"postpone startup notifications until such time as the container is marked " +
			"healthy, as determined by Podman healthchecks. Note that this requires " +
			"setting up a container healthcheck, see the HealthCmd option for more.\"",
		DefaultSeverity: Warning,
		Check:           checkQD020,
	})

	Register(&Rule{
		ID:      "QD021",
		Summary: "Restart policy has no exact systemd equivalent",
		Rationale: "compose's `unless-stopped` is not a systemd restart policy. systemd " +
			"does not reject it: it logs a parse failure and carries on with no restart " +
			"policy at all, so the container silently never restarts. The honest " +
			"translation is Restart=always with an [Install] section, since systemd " +
			"separates the restart policy from enablement.",
		Citation: "systemd.service(5), Restart= lists the accepted values, which do not " +
			"include unless-stopped. Observed behaviour: running systemd-analyze verify " +
			"over the generated service reports a parse failure for " +
			"Restart=unless-stopped and continues, leaving the unit with no restart " +
			"policy.",
		DefaultSeverity: Error,
		Check:           checkQD021,
	})
}

// networkIsolating reports whether a Network= value puts the container
// somewhere that sibling DNS cannot work.
func networkIsolating(value string) bool {
	v := lower(value)
	return v == "host" || v == "none"
}

// hasSharedNetwork reports whether a unit joins a user-defined network, which
// is what enables DNS between containers.
func hasSharedNetwork(u *ir.Unit) bool {
	for _, n := range u.Networks {
		if networkIsolating(n) {
			continue
		}
		// A .network unit reference, a .container reference (sharing another
		// container's stack), or a named network all provide DNS.
		if n != "" && !strings.EqualFold(n, "bridge") && !strings.EqualFold(n, "podman") {
			return true
		}
	}
	return false
}

func checkQD030(c *Context) []Finding {
	containers := c.Project.Containers()
	// With a single container there are no siblings to resolve.
	if len(containers) < 2 {
		return nil
	}

	// Containers in a pod share a network namespace and reach each other on
	// localhost, so service-name DNS does not apply. See ADR-0001.
	var findings []Finding
	for _, u := range containers {
		if u.Pod != "" {
			continue
		}
		if hasSharedNetwork(u) {
			continue
		}
		// A container explicitly placed on the host or no network has made a
		// deliberate choice; reporting it would be noise.
		isolated := false
		for _, n := range u.Networks {
			if networkIsolating(n) {
				isolated = true
			}
		}
		if isolated {
			continue
		}

		findings = append(findings, Finding{
			RuleID:     "QD030",
			Severity:   Error,
			Confidence: Confirmed,
			Unit:       u.Path,
			Line:       u.KeyLine("Network"),
			Message: fmt.Sprintf("%s is on the default network, where DNS is disabled, so it cannot resolve the other %d containers in this project by name",
				u.Name, len(containers)-1),
			Remediation: fmt.Sprintf("Create a shared network unit and join it. In a file called "+
				"`%s.network`:\n\n"+
				"    [Network]\n"+
				"    NetworkName=%s\n\n"+
				"    [Install]\n"+
				"    WantedBy=default.target\n\n"+
				"then in each container unit:\n\n"+
				"    Network=%s.network\n\n"+
				"Podman's default network reports dns_enabled: false, so this is required "+
				"for sibling names to resolve at all, not merely tidier.",
				defaultNetworkName(c), defaultNetworkName(c), defaultNetworkName(c)),
		})
	}
	return findings
}

// defaultNetworkName suggests a name for the shared network, reusing one the
// project already defines rather than inventing a second.
func defaultNetworkName(c *Context) string {
	for _, u := range c.Project.Units {
		if u.Kind == ir.KindNetwork {
			return u.Name
		}
	}
	return "shared"
}

func checkQD031(c *Context) []Finding {
	threshold, known := c.Host.UnprivilegedPortStart()
	confidence := Confirmed
	if !known {
		// Without host context, fall back to the kernel default so the rule
		// still says something useful, but word it as a possibility.
		threshold = 1024
		confidence = Possible
	}

	rootless, rootlessKnown := c.Host.Rootless()
	if rootlessKnown && !rootless {
		// A rootful Podman binds low ports freely.
		return nil
	}

	var findings []Finding
	for _, u := range c.Project.Units {
		for _, p := range u.Ports {
			if p.HostPort == 0 || p.HostPort >= threshold {
				continue
			}

			findings = append(findings, Finding{
				RuleID:     "QD031",
				Severity:   Warning,
				Confidence: confidence,
				Unit:       u.Path,
				Line:       p.Line,
				Message: hedge(confidence,
					fmt.Sprintf("port %d is below this system's unprivileged threshold of %d, so a rootless container cannot bind it",
						p.HostPort, threshold),
					fmt.Sprintf("port %d is below the usual unprivileged threshold of %d, so a rootless container would not be able to bind it",
						p.HostPort, threshold)),
				Remediation: fmt.Sprintf("Publish a high port and redirect to it, which needs no privilege:\n\n"+
					"    PublishPort=%d:%d\n\n"+
					"Or lower the threshold system-wide, which affects every unprivileged "+
					"process:\n\n"+
					"    echo 'net.ipv4.ip_unprivileged_port_start=%d' | sudo tee /etc/sysctl.d/50-unprivileged-ports.conf\n"+
					"    sudo sysctl --system",
					p.HostPort+8000, p.ContainerPort, p.HostPort),
			})
		}
	}
	return findings
}

func checkQD032(c *Context) []Finding {
	existing, known := c.Host.ExistingUnitNames()
	if !known {
		return nil
	}

	taken := make(map[string]bool, len(existing))
	for _, name := range existing {
		taken[name] = true
	}

	var findings []Finding
	for _, u := range c.Project.Units {
		// Compare the file name, which is what the search path collides on.
		fileName := u.Name + "." + string(u.Kind)
		if !taken[fileName] {
			continue
		}

		findings = append(findings, Finding{
			RuleID:     "QD032",
			Severity:   Error,
			Confidence: Confirmed,
			Unit:       u.Path,
			Message: fmt.Sprintf("a unit called %s is already installed in the Quadlet search path, and would be replaced",
				fileName),
			Remediation: fmt.Sprintf("Rename this unit, or remove the installed one first. Note that "+
				"Quadlet also names the Podman objects it creates after the unit: %s "+
				"would create `systemd-%s`, so a rename changes the object name too.",
				fileName, u.Name),
		})
	}
	return findings
}

func checkQD020(c *Context) []Finding {
	var findings []Finding

	for _, u := range c.Project.Units {
		if u.Source == nil {
			continue
		}
		// After= on a sibling container is the pattern that looks like a
		// dependency but is not a readiness gate.
		for _, after := range u.Source.Values("Unit", "After") {
			target := strings.TrimSuffix(strings.TrimSpace(after), ".service")
			dep, ok := c.Project.UnitByName(target, ir.KindContainer)
			if !ok {
				continue
			}
			// If the dependency already notifies on health, the gap is
			// closed and there is nothing to say.
			if lower(dep.Notify) == "healthy" {
				continue
			}

			remediation := fmt.Sprintf("On %s, make the service report started only once the container "+
				"is healthy:\n\n"+
				"    Notify=healthy\n\n"+
				"This requires a healthcheck on that container. ", dep.Name)
			if !dep.HasHealthCmd {
				remediation += fmt.Sprintf("%s has none yet, so add one first, for example:\n\n"+
					"    HealthCmd=/usr/bin/true\n"+
					"    HealthInterval=10s\n"+
					"    HealthStartPeriod=30s\n\n"+
					"replacing the command with a real readiness check for that service.",
					dep.Name)
			} else {
				remediation += "It already has one, so this is a one-line change."
			}

			findings = append(findings, Finding{
				RuleID:     "QD020",
				Severity:   Warning,
				Confidence: Confirmed,
				Unit:       u.Path,
				Line:       u.KeyLine("After"),
				Message: fmt.Sprintf("%s is ordered after %s, but systemd ordering waits for the container to start, not to become ready",
					u.Name, dep.Name),
				Remediation: remediation,
			})
		}
	}
	return findings
}

func checkQD021(c *Context) []Finding {
	var findings []Finding

	for _, u := range c.Project.Units {
		// A unit can only carry a systemd policy, so `unless-stopped` here
		// means someone translated compose by hand and kept the word.
		if lower(u.Restart) != "unless-stopped" {
			continue
		}

		findings = append(findings, Finding{
			RuleID:     "QD021",
			Severity:   Error,
			Confidence: Confirmed,
			Unit:       u.Path,
			Line:       u.KeyLine("Restart"),
			Message: "Restart=unless-stopped is not a systemd restart policy; systemd ignores it, " +
				"so this container silently has no restart policy at all",
			Remediation: "systemd has no equivalent of compose's unless-stopped, and does not " +
				"reject it either: it logs \"Failed to parse Restart=unless-stopped, " +
				"ignoring\" and leaves the unit with no policy. Use:\n\n" +
				"    Restart=always\n\n" +
				"together with an [Install] section. systemd respects an explicit " +
				"`systemctl stop` for as long as the machine is up, and the [Install] " +
				"section starts the unit again at boot, which is what unless-stopped " +
				"was for.",
		})
	}
	return findings
}
