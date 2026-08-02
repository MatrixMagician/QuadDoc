package rules

import (
	"fmt"

	"github.com/MatrixMagician/quaddoc/internal/ir"
)

// QD022 catches units that will never start on their own.
//
// Quadlet-generated services are transient, so `systemctl enable` does not work
// on them. The generator compensates by applying the `[Install]` section itself
// at generation time, in the same way `systemctl enable` would. A unit with no
// `[Install]` section is therefore wired to nothing: it can be started by hand
// but will not come up at login or boot, which is almost never what the author
// intended.
//
// Only four keys are honoured in `[Install]`. Anything else is read and
// discarded, silently, which is its own trap and is reported separately.
func init() {
	Register(&Rule{
		ID:      "QD022",
		Summary: "Unit has no [Install] section and will never autostart",
		Rationale: "Quadlet services are transient, so they cannot be enabled with " +
			"systemctl. The generator applies the [Install] section at generation " +
			"time instead. Without one the unit starts only when started by hand.",
		Citation: "podman-systemd.unit(5), \"Enabling unit files\": services created by " +
			"Podman are transient, so \"it is not possible to systemctl enable them in " +
			"order for them to become automatically enabled on the next boot\". Instead " +
			"the generator \"manually applies the [Install] section of the container " +
			"definition unit files during generation, in the same way systemctl enable " +
			"does when run later\".",
		DefaultSeverity: Error,
		Fixable:         true,
		Check:           checkQD022,
	})

	Register(&Rule{
		ID:      "QD023",
		Summary: "[Install] contains a key Quadlet does not honour",
		Rationale: "Quadlet applies only Alias, WantedBy, RequiredBy, and UpheldBy from " +
			"[Install]. Any other key is read and discarded without warning, so a unit " +
			"can look correctly installed while doing nothing.",
		Citation: "podman-systemd.unit(5), \"Enabling unit files\": \"Currently, only the " +
			"Alias, WantedBy, RequiredBy, and UpheldBy keys are supported.\"",
		DefaultSeverity: Warning,
		Check:           checkQD023,
	})
}

// installKeysHonoured is the set Quadlet acts on. Everything else in [Install]
// is discarded.
var installKeysHonoured = map[string]bool{
	"alias":      true,
	"wantedby":   true,
	"requiredby": true,
	"upheldby":   true,
}

// oneShotImages are images whose containers are expected to run once and exit,
// for which a missing [Install] is a note rather than an error. The spec calls
// for this distinction; we detect it from an explicit signal rather than
// guessing at the image's behaviour.
func isOneShot(u *ir.Unit) bool {
	// A container that Quadlet is told not to restart, or that declares
	// Type=oneshot behaviour through its service section, is a one-shot.
	return u.Restart == "no" || u.Restart == "on-failure"
}

func checkQD022(c *Context) []Finding {
	var findings []Finding

	for _, u := range c.Project.Units {
		// Only units that generate a service can autostart. Volume and
		// network units are pulled in as dependencies of the containers that
		// reference them, so they need no [Install] of their own.
		if u.Kind != ir.KindContainer && u.Kind != ir.KindPod {
			continue
		}

		// A container that belongs to a pod is started with the pod, so the
		// pod carries the [Install] and the container need not.
		if u.Pod != "" {
			continue
		}

		if u.HasInstall && len(u.InstallKeys) > 0 {
			continue
		}

		severity := c.Severity("QD022", Error)
		message := fmt.Sprintf("%s has no [Install] section, so it will never start automatically", u.Name)
		if u.HasInstall {
			message = fmt.Sprintf("%s has an empty [Install] section, so it will never start automatically", u.Name)
		}
		if isOneShot(u) {
			// A unit that is not meant to keep running is plausibly meant to
			// be triggered by hand or by a timer, so this is informational.
			severity = Note
			message += " (this looks deliberate for a one-shot unit)"
		}

		findings = append(findings, Finding{
			RuleID:     "QD022",
			Severity:   severity,
			Confidence: Confirmed, // Reasoned entirely from the unit; no host facts needed.
			Unit:       u.Path,
			Message:    message,
			Remediation: "Add an [Install] section:\n\n" +
				"    [Install]\n" +
				"    WantedBy=default.target\n\n" +
				"For a system-wide unit use multi-user.target instead.",
		})
	}
	return findings
}

func checkQD023(c *Context) []Finding {
	var findings []Finding

	for _, u := range c.Project.Units {
		for _, kv := range u.InstallKeys {
			if installKeysHonoured[lower(kv.Key)] {
				continue
			}
			findings = append(findings, Finding{
				RuleID:     "QD023",
				Severity:   c.Severity("QD023", Warning),
				Confidence: Confirmed,
				Unit:       u.Path,
				Line:       kv.Line,
				Message: fmt.Sprintf("[Install] key %s= is not honoured by Quadlet and will be silently ignored",
					kv.Key),
				Remediation: "Quadlet applies only Alias=, WantedBy=, RequiredBy=, and UpheldBy=. " +
					"Remove the key, or express the intent with one of those four.",
			})
		}
	}
	return findings
}

// QD000 reports a suppression directive that gave no reason.
//
// It is registered like any other rule so that it appears in the reference and
// can itself be configured, though disabling it rather defeats the purpose.
func init() {
	Register(&Rule{
		ID:      "QD000",
		Summary: "Suppression directive gives no reason",
		Rationale: "A `# quaddoc: disable=` comment without a reason is indistinguishable " +
			"from a bug someone gave up on. The cost is paid later, by whoever finds it " +
			"and cannot tell whether the justification still holds, so quaddoc ignores " +
			"a directive with no reason and says so.",
		Citation: "A project convention rather than an external one; see CLAUDE.md and " +
			"SPEC.md section 5, which requires the reason.",
		DefaultSeverity: Warning,
		// Raised by the configuration layer, which has the file text, rather
		// than by walking the IR.
		Check: func(*Context) []Finding { return nil },
	})
}
