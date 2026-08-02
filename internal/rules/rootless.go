package rules

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/MatrixMagician/quaddoc/internal/hostctx"
	"github.com/MatrixMagician/quaddoc/internal/ir"
)

// The rootless UID/GID family, QD010 to QD013.
func init() {
	Register(&Rule{
		ID:      "QD010",
		Summary: "Container user and host bind mount ownership will not line up",
		Rationale: "Rootless Podman maps container UIDs through the user's subordinate " +
			"range, so UID 1000 inside the container is not UID 1000 on the host. A " +
			"bind mount owned by the host user appears as owned by nobody inside the " +
			"container, and writes are denied. Neither the container nor the host is " +
			"misconfigured; the mapping simply does not do what people expect.",
		Citation: "podman-run(1), --userns=keep-id: maps the current user's UID into " +
			"the container so that host-owned files are accessible. podman-systemd." +
			"unit(5), UserNS= and Volume= :U.",
		DefaultSeverity: Warning,
		Check:           checkQD010,
	})

	Register(&Rule{
		ID:      "QD011",
		Summary: "Named group in GroupAdd= will not resolve to the host group",
		Rationale: "GroupAdd= resolves names against the container's /etc/group, not the " +
			"host's. A host group name either does not exist in the image, so the unit " +
			"fails to start, or exists with a different GID, so the container silently " +
			"joins the wrong group. Neither is what the author meant by naming a host " +
			"group.",
		Citation: "podman-systemd.unit(5), GroupAdd=: \"Also supports the keep-groups " +
			"special flag.\" podman-run(1), --group-add, documents keep-groups as passing " +
			"the invoking user's supplementary group access into the container, and notes " +
			"it is \"Currently only available with the crun OCI runtime\".",
		DefaultSeverity: Error,
		Check:           checkQD011,
	})

	Register(&Rule{
		ID:      "QD012",
		Summary: "Named volume will not be chowned for a non-root container",
		Rationale: "Podman chowns a named volume's mount point on first use, so the " +
			"common case of a fresh volume and a non-root image needs no help. The " +
			"failure is the exception: once a volume has been populated, or when it is " +
			"a bind masquerading as a named volume, that automatic chown no longer " +
			"applies and the non-root process is denied.",
		Citation: "podman-run(1), \"Chowning Volume Mounts\": the chown occurs only when " +
			"\"The volume was not used yet (has NeedsChown set to true)\", \"The volume " +
			"is empty or has not been copied up yet\", the volume is not on an external " +
			"driver, and the driver is not \"image\". Reproduced on Podman 5.8.4: a " +
			"fresh volume was chowned to 1234:1234 automatically, while a volume first " +
			"populated by root gave Permission denied to a later --user 1234 container.",
		DefaultSeverity: Warning,
		Check:           checkQD012,
	})

	Register(&Rule{
		ID:      "QD013",
		Summary: "Container UID or GID falls outside the available subordinate range",
		Rationale: "Rootless Podman can only map IDs within the ranges allocated to the " +
			"user in /etc/subuid and /etc/subgid. An ID beyond the end of the range " +
			"cannot be mapped, and the container fails to start with an error that " +
			"names the ID but not the reason.",
		Citation: "subuid(5) and subgid(5); podman-run(1), --uidmap. Rootless Podman " +
			"maps container IDs through these ranges, so the largest usable ID is the " +
			"range's size minus one.",
		DefaultSeverity:  Error,
		NeedsHostContext: true,
		Check:            checkQD013,
	})
}

// runsAsNonRoot reports the container's UID when it is explicitly set to
// something other than root.
func runsAsNonRoot(u *ir.Unit) (int, bool) {
	if u.User == "" {
		// No User= means the image's own USER applies, which we cannot see
		// from here. Staying silent is right: guessing would produce a
		// finding on most correctly configured units.
		return 0, false
	}
	uid, err := strconv.Atoi(strings.TrimSpace(u.User))
	if err != nil {
		// A name rather than a number. It resolves inside the container, so
		// we cannot tell what it maps to.
		return 0, false
	}
	return uid, uid != 0
}

func checkQD010(c *Context) []Finding {
	var findings []Finding

	for _, u := range c.Project.Units {
		uid, nonRoot := runsAsNonRoot(u)
		if !nonRoot {
			continue
		}
		// keep-id already aligns the host user with the container user, which
		// is the recommended answer, so there is nothing to report.
		if strings.Contains(u.UserNS, "keep-id") {
			continue
		}

		for _, m := range u.Mounts {
			if m.Type != ir.MountBind {
				continue
			}
			// A read-only mount of world-readable content usually works, so
			// reporting it would be noise.
			if m.HasOption("ro") {
				continue
			}
			// :U asks Podman to chown the source to the container's mapped
			// IDs, which is one of the two right answers.
			if m.HasOption("U") {
				continue
			}

			findings = append(findings, Finding{
				Severity:   Warning,
				Confidence: Possible,
				Unit:       u.Path,
				Line:       m.Line,
				Message: fmt.Sprintf("container runs as UID %d and writes to the bind mount %s, whose host ownership will not match",
					uid, m.Source),
				Remediation: fmt.Sprintf("Under rootless Podman, UID %d inside the container maps to a "+
					"subordinate UID on the host, not to %d, so files the host user owns "+
					"appear unowned inside. Two ways to fix it:\n\n"+
					"  1. Run the container as the host user:\n\n"+
					"         UserNS=keep-id\n\n"+
					"     Best when the host user should keep owning the files, for "+
					"example a directory you edit yourself.\n\n"+
					"  2. Let Podman chown the source to the mapped IDs:\n\n"+
					"         Volume=%s\n\n"+
					"     Best when the container owns the data outright. Note that this "+
					"rewrites ownership on the host and walks every file, so it is slow "+
					"on large trees.",
					uid, uid, withOption(m, "U")),
			})
		}
	}
	return findings
}

func checkQD011(c *Context) []Finding {
	var findings []Finding

	for _, u := range c.Project.Units {
		for i, group := range u.GroupAdd {
			g := strings.TrimSpace(group)
			if g == "" || g == "keep-groups" {
				continue
			}
			// A numeric GID is passed straight through and means what it says
			// inside the container, so it is not this rule's business.
			if _, err := strconv.Atoi(g); err == nil {
				continue
			}

			findings = append(findings, Finding{
				Severity:   Error,
				Confidence: Possible,
				Unit:       u.Path,
				Line:       u.KeyLine("GroupAdd") + i,
				Message: fmt.Sprintf("GroupAdd=%s names a group that must exist inside the container, not on the host",
					g),
				Remediation: fmt.Sprintf("If you meant to pass through the host user's group access, which is "+
					"the usual reason for this, use:\n\n"+
					"    GroupAdd=keep-groups\n\n"+
					"That grants the container the invoking user's supplementary groups, "+
					"and is the only way to reach host files readable only by group. It "+
					"requires the crun runtime, which is the default on Fedora.\n\n"+
					"If %q really is a group inside the image, give its numeric GID "+
					"instead so it does not depend on the image's /etc/group.", g),
			})
		}
	}
	return findings
}

func checkQD012(c *Context) []Finding {
	var findings []Finding

	users := c.Project.NamedVolumeUsers()

	for _, u := range c.Project.Units {
		uid, nonRoot := runsAsNonRoot(u)
		if !nonRoot {
			continue
		}

		for _, m := range u.Mounts {
			if m.Type != ir.MountNamed {
				continue
			}
			// :U asks for the chown explicitly, so there is nothing to warn
			// about.
			if m.HasOption("U") {
				continue
			}

			reason, affected := autoChownDefeated(c, u, m, users)
			if !affected {
				// The common case: a fresh volume gets chowned automatically
				// on first use. Reporting it here is exactly the false
				// positive the spec's original wording would have produced.
				continue
			}

			findings = append(findings, Finding{
				Severity:   Warning,
				Confidence: Possible,
				Unit:       u.Path,
				Line:       m.Line,
				Message: fmt.Sprintf("volume %s will not be chowned for the container's UID %d: %s",
					m.Source, uid, reason),
				Remediation: fmt.Sprintf("Podman chowns a named volume only on first use, and only while it "+
					"is still empty. Ask for it explicitly:\n\n"+
					"    Volume=%s\n\n"+
					"The :U option chowns the source to the container's mapped UID and "+
					"GID. It walks every file, so on a volume with many inodes it will "+
					"delay startup noticeably.\n\n"+
					"Alternatively, have the image itself chown the directory in an "+
					"entrypoint, which keeps the cost inside the container.",
					withOption(m, "U")),
			})
		}
	}
	return findings
}

// autoChownDefeated reports whether Podman's first-use chown will fail to help
// this container, and why.
//
// This is the corrected form of the spec's QD012. The spec would have warned
// whenever a non-root container mounted a named volume with no chown strategy,
// but Podman handles that case itself; see the rule's citation. Only the
// documented exceptions are worth a finding.
func autoChownDefeated(c *Context, u *ir.Unit, m ir.Mount, users map[string][]*ir.Unit) (string, bool) {
	// A volume shared with a container running as root: whichever starts
	// first claims the ownership, and by the time the non-root container
	// mounts it, it is no longer empty.
	for _, other := range users[m.Source] {
		if other == u {
			continue
		}
		if _, otherNonRoot := runsAsNonRoot(other); !otherNonRoot && other.User == "" {
			// Another unit mounts it and does not set User=, so it may well
			// run as root and populate the volume first.
			return fmt.Sprintf("%s also mounts it and may populate it as root first, "+
				"after which the automatic chown no longer applies", other.Name), true
		}
		if otherUID, otherNonRoot := runsAsNonRoot(other); otherNonRoot {
			if uid, _ := runsAsNonRoot(u); otherUID != uid {
				return fmt.Sprintf("%s mounts it as UID %d, so the two containers cannot "+
					"both own it", other.Name, otherUID), true
			}
		}
	}

	// A `local` driver volume backed by a host directory is a bind mount
	// wearing a named volume's clothes: the host directory keeps its own
	// ownership and the first-use chown does not save you.
	if m.UnitRef != "" {
		if vol, ok := c.Project.UnitByName(m.UnitRef, ir.KindVolume); ok && vol.Source != nil {
			device := lastValue(vol.Source.Values("Volume", "Device"))
			options := lastValue(vol.Source.Values("Volume", "Options"))
			if device != "" && strings.Contains(options, "bind") {
				return fmt.Sprintf("%s.volume is a bind to %s, so it keeps that directory's "+
					"ownership rather than being chowned", m.UnitRef, device), true
			}
		}
	}

	return "", false
}

func lastValue(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[len(values)-1]
}

func checkQD013(c *Context) []Finding {
	var findings []Finding

	rootless, known := c.Host.Rootless()
	if known && !rootless {
		// Running as root, so subordinate ranges do not constrain anything.
		return nil
	}

	subUID, haveUID := c.Host.SubUIDRanges()
	subGID, haveGID := c.Host.SubGIDRanges()
	if !haveUID && !haveGID {
		// Answerable only with host context.
		return nil
	}

	for _, u := range c.Project.Units {
		if uid, err := strconv.Atoi(strings.TrimSpace(u.User)); err == nil && haveUID {
			if f, bad := outsideRange(c, u, "User", uid, subUID, "subuid"); bad {
				findings = append(findings, f)
			}
		}
		if gid, err := strconv.Atoi(strings.TrimSpace(u.Group)); err == nil && haveGID {
			if f, bad := outsideRange(c, u, "Group", gid, subGID, "subgid"); bad {
				findings = append(findings, f)
			}
		}
	}
	return findings
}

// outsideRange builds a finding when an ID cannot be mapped.
func outsideRange(c *Context, u *ir.Unit, key string, id int, ranges []hostctx.IDRange, file string) (Finding, bool) {
	// UID 0 is always mappable: it becomes the invoking user.
	if id == 0 {
		return Finding{}, false
	}
	// Podman maps container ID 0 to the host user and IDs from 1 upwards into
	// the subordinate range, so the largest usable ID is the total size.
	var total int
	for _, r := range ranges {
		total += r.Count
	}
	if id <= total {
		return Finding{}, false
	}

	return Finding{
		Severity:   Error,
		Confidence: Confirmed,
		Unit:       u.Path,
		Line:       u.KeyLine(key),
		Message: fmt.Sprintf("%s=%d is beyond the %d subordinate IDs available to this user, so the container cannot start",
			key, id, total),
		Remediation: fmt.Sprintf("Either use an ID within the range, or extend the allocation in "+
			"/etc/%s and re-run `podman system migrate`:\n\n"+
			"    sudo usermod --add-sub%ss $USER:100000:65536\n\n"+
			"The ranges are per user and are read at container start, not at login.",
			file, strings.TrimSuffix(file, "id")),
	}, true
}
