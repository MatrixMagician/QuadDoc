package rules

import (
	"fmt"
	"strings"
)

// QD042 catches keys Quadlet does not recognise.
//
// Per ADR-0002 this ships narrow: it reports keys that exist in no released
// Quadlet, not keys that are merely newer than the reader's Podman. Per-version
// deltas would need a table encoding which key arrived in which release, and a
// stale table produces confident, wrong findings. The key set here is generated
// from podman-systemd.unit(5) rather than hand-maintained; see
// internal/rules/genkeys.
func init() {
	Register(&Rule{
		ID:      "QD042",
		Summary: "Key is not recognised by Quadlet and will be ignored",
		Rationale: "Quadlet reads the keys it knows and ignores the rest without " +
			"complaint, so a typo'd key looks like configuration that simply does not " +
			"work. This most often bites when a key is spelled as its podman flag " +
			"(Volumes= for Volume=) or as the compose key it came from.",
		Citation: "podman-systemd.unit(5) lists the keys each unit type accepts. The set " +
			"is generated from the installed manual page by internal/rules/genkeys; see " +
			"docs/adr/0002-minimum-podman-version.md for why per-version deltas are not " +
			"attempted in v1.",
		DefaultSeverity: Warning,
		Check:           checkQD042,
	})
}

// commonMistakes maps a wrong key to the right one, so the finding can suggest
// rather than merely reject. These are the errors that come from writing
// Quadlet with podman-run(1) or a compose file open beside you.
var commonMistakes = map[string]string{
	"VOLUMES":          "Volume",
	"PORTS":            "PublishPort",
	"PORT":             "PublishPort",
	"PUBLISHPORTS":     "PublishPort",
	"ENVIRONMENTS":     "Environment",
	"ENV":              "Environment",
	"NETWORKS":         "Network",
	"COMMAND":          "Exec",
	"CMD":              "Exec",
	"ENTRYPOINT":       "Entrypoint",
	"RESTART":          "Restart= belongs in the [Service] section",
	"IMAGES":           "Image",
	"LABELS":           "Label",
	"SECRETS":          "Secret",
	"DEVICES":          "AddDevice",
	"DEVICE":           "AddDevice",
	"CAPABILITIES":     "AddCapability",
	"CAPADD":           "AddCapability",
	"CAPDROP":          "DropCapability",
	"HOSTNAME":         "HostName",
	"WORKDIR":          "WorkingDir",
	"WORKINGDIRECTORY": "WorkingDir",
	"USERNS":           "UserNS",
	"HEALTHCHECK":      "HealthCmd",
	"GROUPADDS":        "GroupAdd",
	"TMPFS":            "Tmpfs",
	"SHMSIZE":          "ShmSize",
	"AUTOUPDATES":      "AutoUpdate",
}

func checkQD042(c *Context) []Finding {
	var findings []Finding

	for _, u := range c.Project.Units {
		if u.Source == nil {
			continue
		}
		section := u.Kind.Section()
		if section == "" {
			continue
		}

		accepted, ok := knownKeys[section]
		if !ok {
			continue
		}

		for _, e := range u.Entries {
			if !strings.EqualFold(e.Section, section) {
				continue
			}
			if accepted[canonicalKey(accepted, e.Key)] {
				continue
			}

			message := fmt.Sprintf("%s= is not a Quadlet key for [%s] and will be ignored",
				e.Key, section)
			remediation := fmt.Sprintf("Quadlet reads only the keys it knows and ignores the rest without "+
				"complaint, so this line has no effect. Check the spelling against "+
				"`man podman-systemd.unit`, or run `quaddoc rules QD042`.\n\n"+
				"If the key is genuinely newer than the Podman this was checked "+
				"against (%s), you can pass it through with PodmanArgs=.",
				generatedFromPodman)

			if suggestion, known := commonMistakes[strings.ToUpper(e.Key)]; known {
				if strings.Contains(suggestion, " ") {
					remediation = suggestion + ".\n\n" + remediation
				} else {
					message = fmt.Sprintf("%s= is not a Quadlet key for [%s]; did you mean %s=?",
						e.Key, section, suggestion)
					remediation = fmt.Sprintf("Rename the key:\n\n    %s=%s\n\n"+
						"Quadlet ignores keys it does not know, so as written this line "+
						"does nothing.", suggestion, e.Value)
				}
			}

			findings = append(findings, Finding{
				RuleID:      "QD042",
				Severity:    Warning,
				Confidence:  Confirmed,
				Unit:        u.Path,
				Line:        e.Line,
				Message:     message,
				Remediation: remediation,
			})
		}
	}
	return findings
}

// canonicalKey matches a key case-insensitively against the accepted set,
// since systemd itself is case-insensitive about key names.
func canonicalKey(accepted map[string]bool, key string) string {
	if accepted[key] {
		return key
	}
	for candidate := range accepted {
		if strings.EqualFold(candidate, key) {
			return candidate
		}
	}
	return key
}
