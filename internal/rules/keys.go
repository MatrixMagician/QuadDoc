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
		Summary: "Key is not recognised by Quadlet, so the unit is not generated",
		Rationale: "The Quadlet generator rejects a unit that sets a key its section does " +
			"not support: it logs \"unsupported key\" and creates no service for that " +
			"unit, so `systemctl start` then reports the unit as not found. This most " +
			"often bites when a key is spelled as its podman flag (Volumes= for " +
			"Volume=) or as the compose key it came from.",
		Citation: "podman-systemd.unit(5) lists the keys each unit type accepts. The set " +
			"is generated from the installed manual page by internal/rules/genkeys; see " +
			"docs/adr/0002-minimum-podman-version.md for why per-version deltas are not " +
			"attempted in v1. The rejection is Podman's checkForUnknownKeys " +
			"(pkg/systemd/quadlet/quadlet.go), which returns `unsupported key '%s' in " +
			"group '%s'` for the whole unit in both 5.0.0 and 5.8.4, the ends of the " +
			"supported range; observed with quadlet -dryrun on 5.8.4. In 5.8.4 the same " +
			"check also covers the [Quadlet] section any unit may carry, against " +
			"supportedQuadletKeys (DefaultDependencies=); 5.0.0 has no [Quadlet] section. " +
			"The 5.8.4 source " +
			"also accepts ServiceName= in every unit section and LogOpt= in [Kube], and " +
			"still honours the deprecated RemapUsers=, RemapUid=, RemapGid=, " +
			"RemapUidSize= and VolatileTmp=, none of which the manual page lists for " +
			"those sections.",
		DefaultSeverity: Error,
		Check:           checkQD042,
	})
}

// generatorOnlyKeys are keys the generator accepts although
// podman-systemd.unit(5) does not list them for that section. This is the
// whole of that gap, found by comparing knownKeys with each section's
// supported-key table in Podman 5.8.4's quadlet.go, less the deprecated keys
// below. TestQD042MatchesTheGenerator pins it against the real generator.
var generatorOnlyKeys = map[string]map[string]bool{
	"Container": {"ServiceName": true},
	"Volume":    {"ServiceName": true},
	"Network":   {"ServiceName": true},
	"Kube":      {"ServiceName": true, "LogOpt": true},
	"Build":     {"ServiceName": true},
	"Image":     {"ServiceName": true},
}

// deprecatedKeys are keys the generator still honours in the given sections but
// marks deprecated in its source (quadlet.go in both 5.0.0 and 5.8.4), mapped to
// what replaces each. They are absent from podman-systemd.unit(5), so without
// this table QD042 would call working configuration unknown.
var deprecatedKeys = map[string]map[string]string{
	"Container": {
		"RemapUsers": "UserNS=", "RemapUid": "UIDMap= (or UserNS=keep-id:uid=)",
		"RemapGid": "GIDMap= (or UserNS=keep-id:gid=)", "RemapUidSize": "UserNS=auto:size=",
		"VolatileTmp": "Tmpfs=/tmp",
	},
	"Pod": {
		"RemapUsers": "UserNS=", "RemapUid": "UIDMap= (or UserNS=keep-id:uid=)",
		"RemapGid": "GIDMap= (or UserNS=keep-id:gid=)", "RemapUidSize": "UserNS=auto:size=",
	},
	"Kube": {
		"RemapUsers": "UserNS=", "RemapUid": "UserNS=keep-id:uid= or UserNS=auto:uidmapping=",
		"RemapGid": "UserNS=keep-id:gid= or UserNS=auto:gidmapping=", "RemapUidSize": "UserNS=auto:size=",
	},
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

		if _, ok := knownKeys[section]; !ok {
			continue
		}

		for _, e := range u.Entries {
			// The generator checks the unit's own section and the [Quadlet]
			// section every unit may carry; it passes other sections to systemd.
			if e.Section != section && e.Section != "Quadlet" {
				continue
			}
			accepted := knownKeys[e.Section]
			if accepted[e.Key] || generatorOnlyKeys[e.Section][e.Key] {
				continue
			}

			if replacement, ok := deprecatedKeys[e.Section][e.Key]; ok {
				findings = append(findings, Finding{
					Severity:   Note,
					Confidence: Confirmed,
					Unit:       u.Path,
					Line:       e.Line,
					Message: fmt.Sprintf("%s= is deprecated; the generator still honours it, but it is no longer documented",
						e.Key),
					Remediation: fmt.Sprintf("Express the same setting with %s, the documented "+
						"equivalent. The deprecated key works on the Podman this was checked "+
						"against (%s), but may be removed from a later release.",
						replacement, generatedFromPodman),
				})
				continue
			}

			base := u.Name + "." + string(u.Kind)
			message := fmt.Sprintf("%s= is not a Quadlet key for [%s], so the generator rejects %s and creates no service for it",
				e.Key, e.Section, base)
			remediation := fmt.Sprintf("The generator stops at the first key it does not know and "+
				"generates nothing for this unit. Check the spelling against "+
				"`man podman-systemd.unit`, or run `quaddoc rules QD042`.\n\n"+
				"If the key is genuinely newer than the Podman this was checked "+
				"against (%s), you can pass it through with PodmanArgs=.",
				generatedFromPodman)

			suggestion, known := commonMistakes[strings.ToUpper(e.Key)]
			if !known {
				suggestion, known = caseMismatch(accepted, e.Key)
			}
			if known {
				if strings.Contains(suggestion, " ") {
					remediation = suggestion + ".\n\n" + remediation
				} else {
					message = fmt.Sprintf("%s= is not a Quadlet key for [%s], so the generator rejects %s; did you mean %s=?",
						e.Key, e.Section, base, suggestion)
					remediation = fmt.Sprintf("Rename the key:\n\n    %s=%s\n\n"+
						"The generator rejects a unit with a key it does not know, so as "+
						"written no service is created for it.", suggestion, e.Value)
				}
			}

			findings = append(findings, Finding{
				Severity:    Error,
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

// caseMismatch finds the accepted key a wrongly-cased key was meant to be.
// Quadlet matches keys exactly and rejects `image=` as an unsupported key
// (verified against Podman 5.8.4), so the case is the whole mistake.
func caseMismatch(accepted map[string]bool, key string) (string, bool) {
	for candidate := range accepted {
		if strings.EqualFold(candidate, key) {
			return candidate, true
		}
	}
	return "", false
}
