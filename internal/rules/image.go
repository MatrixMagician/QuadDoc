package rules

import "github.com/MatrixMagician/quaddoc/internal/ir"

// QD043 catches a .container unit that names neither a pulled image nor an
// unpacked rootfs, so the Quadlet generator has nothing to build a container
// from.
func init() {
	Register(&Rule{
		ID:      "QD043",
		Summary: "Container unit has neither Image= nor Rootfs=",
		Rationale: "A container has to come from somewhere: a pulled image or an " +
			"already-unpacked rootfs. A unit that sets neither passes lint and then fails " +
			"at generation, which is a worse time to find out than now. There is no " +
			"mechanical fix, because only the author knows which of the two was intended.",
		Citation: "podman-systemd.unit(5), Image=: \"The image to run in the container.\" " +
			"Rootfs=: \"This option conflicts with the Image option.\" Neither is documented " +
			"as optional on its own; the generator confirms it (observed, Podman 5.8.4): " +
			"converting \"x.container\": no Image or Rootfs key specified.",
		DefaultSeverity: Error,
		Check:           checkQD043,
	})
}

func checkQD043(c *Context) []Finding {
	var findings []Finding

	for _, u := range c.Project.Containers() {
		if u.Image != "" || hasRootfs(u) {
			continue
		}
		findings = append(findings, Finding{
			Severity:   Error,
			Confidence: Confirmed,
			Unit:       u.Path,
			Message:    "unit has neither Image= nor Rootfs=, so Quadlet cannot generate it",
			Remediation: "No mechanical fix: decide whether this container runs a pulled " +
				"image or an already-unpacked rootfs, then set the matching key, for " +
				"example:\n\n    Image=docker.io/library/nginx:1.27\n\nor:\n\n" +
				"    Rootfs=/var/lib/mycontainer",
		})
	}
	return findings
}

// hasRootfs reports whether the unit sets a non-empty Rootfs= in [Container].
// Rootfs is not a modelled ir.Unit field, so this reads the raw entries the
// way QD042 does. An empty assignment does not count: the generator treats
// Rootfs= the same as an absent key (observed, Podman 5.8.4).
func hasRootfs(u *ir.Unit) bool {
	for _, e := range u.Entries {
		if e.Section == "Container" && e.Key == "Rootfs" && e.Value != "" {
			return true
		}
	}
	return false
}
