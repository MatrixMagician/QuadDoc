package rules

import (
	"fmt"
	"strings"

	"github.com/MatrixMagician/quaddoc/internal/hostctx"
	"github.com/MatrixMagician/quaddoc/internal/ir"
)

// The SELinux family, QD001 to QD004.
//
// All four turn on a single project-wide fact: how many units mount a given
// bind source. That is computed once, in ir.Project.BindSourceUsage, and shared
// through the Context, which is what stops QD001 and QD002 contradicting each
// other. QD001 fires only when no relabelling option is present; QD002 only
// when `:Z` is present on a shared source. They are mutually exclusive by
// construction rather than by careful wording. See docs/spec-review.md F3.
func init() {
	Register(&Rule{
		ID:      "QD001",
		Summary: "Bind mount has no SELinux relabelling option",
		Rationale: "A bind-mounted host directory keeps whatever label it already had. " +
			"Container processes run confined and are denied access to labels outside " +
			"their type, so the mount appears as permission denied inside the container " +
			"even though the Unix permissions look right. The :z and :Z options relabel " +
			"the source to container_file_t.",
		Citation: "podman-run(1), --volume: \"The Z option tells Podman to label the " +
			"content with a private unshared label.\" The z option is the shared " +
			"equivalent. " +
			"Reproduced on Podman 5.8.4 with SELinux enforcing: a source labelled " +
			"user_tmp_t was denied; after :Z it became " +
			"container_file_t:s0:c235,c710 and the write succeeded.",
		DefaultSeverity:  Error,
		NeedsHostContext: true,
		Fixable:          true,
		Check:            checkQD001,
	})

	Register(&Rule{
		ID:      "QD002",
		Summary: "Private label :Z used on a source shared between units",
		Rationale: "The :Z option applies a label private to one container. When two " +
			"containers both relabel the same source with :Z they overwrite each " +
			"other's category set, so whichever started most recently works and the " +
			"other is denied. The failure looks intermittent and follows restart order, " +
			"which makes it painful to diagnose.",
		Citation: "podman-run(1), --volume: \"The Z option tells Podman to label the " +
			"content with a private unshared label. Only the current container can use " +
			"a private volume.\" Shared content is what :z is for.",
		DefaultSeverity:  Error,
		NeedsHostContext: true,
		Check:            checkQD002,
	})

	Register(&Rule{
		ID:      "QD003",
		Summary: "Relabelling is ineffective or wrong on this filesystem",
		Rationale: "Network and FUSE filesystems do not store SELinux labels per file. " +
			"Relabelling them either fails outright or silently does nothing, and the " +
			"container is denied anyway. Such filesystems take a whole-filesystem label " +
			"through the context= mount option instead.",
		Citation: "mount(8) and selinux(8): context= sets a single label for a whole " +
			"filesystem and is the documented approach for filesystems that do not " +
			"support extended attributes, such as NFS and CIFS. Confirmed from the " +
			"filesystem type in /proc/self/mountinfo under host context.",
		DefaultSeverity:  Warning,
		NeedsHostContext: true,
		Check:            checkQD003,
	})

	Register(&Rule{
		ID:      "QD004",
		Summary: "Relabelling a system directory would break the host",
		Rationale: "Relabelling is recursive. Pointing it at a system directory rewrites " +
			"the labels of files that confined services on the host depend on, and those " +
			"services then fail. The damage outlives the container and is not undone by " +
			"removing it: it takes a restorecon over the affected tree.",
		Citation: "podman-run(1), --volume: \"Note: Do not relabel system files and " +
			"directories. Relabeling system content might cause other confined services " +
			"on the machine to fail.\"",
		DefaultSeverity: Error,
		Check:           checkQD004,
	})
}

// systemPath is a directory that must never be recursively relabelled, with the
// reason it is on the list. The reasons are part of the finding: telling a user
// not to do something without saying why invites them to do it anyway.
type systemPath struct {
	Path   string
	Reason string
}

// systemPaths are the directories where relabelling breaks the host. The list
// errs towards inclusion: a false positive costs the user one `# quaddoc:
// disable` comment, whereas a false negative costs them a broken system and a
// restorecon.
var systemPaths = []systemPath{
	{"/", "relabelling the whole filesystem would break every confined service on the host"},
	{"/home", "home_root_t is what allows confined services and login to work; " +
		"relabelling it breaks user sessions"},
	{"/etc", "etc_t is depended on by nearly every confined service"},
	{"/usr", "usr_t covers the system's own binaries and libraries"},
	{"/var", "relabelling all of /var affects logging, spooling, and system state"},
	{"/var/lib", "var_lib_t is shared by most system services' state directories"},
	{"/var/log", "var_log_t is required by rsyslog, journald, and audit"},
	{"/var/run", "a symlink to /run, whose labels the whole system depends on"},
	{"/run", "runtime state for every service on the machine"},
	{"/boot", "boot_t is required by the bootloader and kernel installation"},
	{"/dev", "device labels are managed by udev and must not be rewritten"},
	{"/proc", "a kernel filesystem whose labels are not stored on disk"},
	{"/sys", "a kernel filesystem whose labels are not stored on disk"},
	{"/tmp", "tmp_t is shared by every service that writes temporary files"},
	{"/opt", "usr_t-derived labels shared by third-party software"},
	{"/srv", "var_t-derived labels shared by system services"},
}

// relabelUnsafeFilesystems do not store per-file SELinux labels, so relabelling
// them is ineffective at best.
var relabelUnsafeFilesystems = map[string]string{
	"nfs":      "NFS does not store SELinux labels per file",
	"nfs4":     "NFS does not store SELinux labels per file",
	"cifs":     "CIFS does not store SELinux labels per file",
	"smb3":     "SMB does not store SELinux labels per file",
	"vfat":     "FAT has no extended attributes, so it cannot hold a label",
	"exfat":    "exFAT has no extended attributes, so it cannot hold a label",
	"ntfs":     "NTFS labels are not managed by SELinux",
	"ntfs3":    "NTFS labels are not managed by SELinux",
	"iso9660":  "a read-only filesystem cannot be relabelled",
	"squashfs": "a read-only filesystem cannot be relabelled",
	"tmpfs":    "tmpfs labels do not survive a reboot, so relabelling is not durable",
	"overlay":  "relabelling an overlay affects the underlying layers unpredictably",
}

// selinuxFinding reports whether an SELinux finding should be raised at all,
// at what severity, and whether the host lowered that severity. See ADR-0004.
//
// The downgraded flag matters because configuration must not raise a finding
// back up after the host has established that it does not apply here.
func selinuxFinding(c *Context, ruleID string, def Severity) (severity Severity, confidence Confidence, downgraded, report bool) {
	mode := c.Host.SELinux()
	severity, keep := DowngradeForSELinux(mode, def)
	if !keep {
		return severity, Confirmed, true, false
	}

	confidence = Possible
	if mode != hostctx.SELinuxUnknown {
		confidence = Confirmed
	}
	return severity, confidence, severity < def, true
}

// hedge words a finding as a possibility when no host context confirmed it.
func hedge(confidence Confidence, confirmed, possible string) string {
	if confidence == Confirmed {
		return confirmed
	}
	return possible
}

func checkQD001(c *Context) []Finding {
	var findings []Finding

	for _, u := range c.Project.Units {
		for _, m := range u.Mounts {
			if m.Type != ir.MountBind || m.HasSELinuxLabel() {
				continue
			}
			// A source under a system path is QD004's business, and telling
			// the user to add :Z there would be actively harmful.
			if _, unsafe := systemPathFor(m.Source); unsafe {
				continue
			}
			// A read-only mount is still subject to the label check: SELinux
			// denies the read, not merely the write.

			severity, confidence, downgraded, report := selinuxFinding(c, "QD001", Error)
			if !report {
				continue
			}

			// Shared sources take :z, private ones :Z. The usage map is
			// computed once for the whole project, so this agrees with QD002
			// by construction.
			option, explanation := "Z", "used only by this unit, so a private label is right"
			if c.BindSourceUsage[m.Source] > 1 {
				option = "z"
				explanation = fmt.Sprintf("mounted by %d units, so a shared label is required; "+
					"a private :Z would let them overwrite each other's categories",
					c.BindSourceUsage[m.Source])
			}

			finding := Finding{
				RuleID:     "QD001",
				Severity:   severity,
				Confidence: confidence,
				Unit:       u.Path,
				Line:       m.Line,
				Message: hedge(confidence,
					fmt.Sprintf("bind mount %s has no SELinux relabelling option, and SELinux is enforcing, so the container will be denied access",
						m.Source),
					fmt.Sprintf("bind mount %s has no SELinux relabelling option, so on an enforcing system the container would be denied access",
						m.Source)),
				Remediation: fmt.Sprintf("Add :%s to the mount, %s:\n\n    Volume=%s\n\n"+
					"Run `quaddoc fix --rule QD001` to apply this.",
					option, explanation, withOption(m, option)),
				// The option was chosen using the project-wide sharing map.
				// Handing it to the fix engine structurally is what stops the
				// fix writing a :Z that QD002 would then flag.
				Fix: map[string]string{"option": option},
			}
			if downgraded {
				finding = finding.MarkHostDowngraded()
			}
			findings = append(findings, finding)
		}
	}
	return findings
}

func checkQD002(c *Context) []Finding {
	var findings []Finding

	for _, u := range c.Project.Units {
		for _, m := range u.Mounts {
			// Only :Z on a genuinely shared source. Without both conditions
			// this is QD001's territory, not ours.
			if m.Type != ir.MountBind || !m.HasOption("Z") {
				continue
			}
			if c.BindSourceUsage[m.Source] < 2 {
				continue
			}

			severity, confidence, downgraded, report := selinuxFinding(c, "QD002", Error)
			if !report {
				continue
			}

			finding := Finding{
				RuleID:     "QD002",
				Severity:   severity,
				Confidence: confidence,
				Unit:       u.Path,
				Line:       m.Line,
				Message: fmt.Sprintf("%s is mounted by %d units but uses the private label :Z, so they will overwrite each other's SELinux categories",
					m.Source, c.BindSourceUsage[m.Source]),
				Remediation: fmt.Sprintf("Use the shared label instead, in every unit that mounts it:\n\n    Volume=%s\n\n"+
					"There is no mechanical fix here: if these containers were meant to be "+
					"isolated from each other, give them separate directories rather than "+
					"weakening the label.", withOption(stripOption(m, "Z"), "z")),
			}
			if downgraded {
				finding = finding.MarkHostDowngraded()
			}
			findings = append(findings, finding)
		}
	}
	return findings
}

func checkQD003(c *Context) []Finding {
	var findings []Finding

	for _, u := range c.Project.Units {
		for _, m := range u.Mounts {
			if m.Type != ir.MountBind || !m.HasSELinuxLabel() {
				continue
			}

			// This rule is answerable only with host context: the filesystem
			// a path lives on is not knowable from the unit alone.
			mount, known := c.Host.MountFor(m.Source)
			if !known {
				continue
			}

			// A filesystem already carrying a context= option has a
			// whole-filesystem label, and relabelling it is both unnecessary
			// and ineffective.
			if strings.Contains(mount.Options, "context=") {
				findings = append(findings, Finding{
					RuleID:     "QD003",
					Severity:   Warning,
					Confidence: Confirmed,
					Unit:       u.Path,
					Line:       m.Line,
					Message: fmt.Sprintf("%s is on a filesystem mounted with context=, so the relabelling option does nothing",
						m.Source),
					Remediation: "Remove the :z or :Z option. The filesystem already carries a " +
						"single label set at mount time, which relabelling cannot change.",
				})
				continue
			}

			reason, unsafe := relabelUnsafeFilesystems[mount.FSType]
			if !unsafe && strings.HasPrefix(mount.FSType, "fuse") {
				reason, unsafe = "FUSE filesystems do not store SELinux labels per file", true
			}
			if !unsafe {
				continue
			}

			findings = append(findings, Finding{
				RuleID:     "QD003",
				Severity:   Warning,
				Confidence: Confirmed,
				Unit:       u.Path,
				Line:       m.Line,
				Message: fmt.Sprintf("%s is on a %s filesystem, where relabelling will not work: %s",
					m.Source, mount.FSType, reason),
				Remediation: fmt.Sprintf("Remove the relabelling option and give the whole filesystem a "+
					"label at mount time instead, in /etc/fstab or the mount unit for %s:\n\n"+
					"    context=\"system_u:object_r:container_file_t:s0\"\n\n"+
					"On a shared filesystem, coordinate that label with whatever else mounts it.",
					mount.MountPoint),
			})
		}
	}
	return findings
}

func checkQD004(c *Context) []Finding {
	var findings []Finding

	for _, u := range c.Project.Units {
		for _, m := range u.Mounts {
			if m.Type != ir.MountBind || !m.HasSELinuxLabel() {
				continue
			}

			sp, unsafe := systemPathFor(m.Source)
			if !unsafe {
				continue
			}

			// This one is reported whatever the SELinux mode. The damage is
			// done at relabel time, and a machine that is permissive today
			// may be enforcing tomorrow with its labels already rewritten.
			findings = append(findings, Finding{
				RuleID:     "QD004",
				Severity:   Error,
				Confidence: Confirmed,
				Unit:       u.Path,
				Line:       m.Line,
				Message: fmt.Sprintf("relabelling %s would rewrite the labels of a system directory: %s",
					m.Source, sp.Reason),
				Remediation: fmt.Sprintf("Remove the :z or :Z option and mount a dedicated subdirectory "+
					"instead, for example a path under %%h or /srv/%s that only this "+
					"container uses.\n\n"+
					"If this has already been applied, repair the labels with:\n\n"+
					"    sudo restorecon -R %s\n\n"+
					"Relabelling is recursive and its effects outlive the container.",
					u.Name, sp.Path),
			})
		}
	}
	return findings
}

// systemPathFor reports whether a path is, or lies directly at, a system
// directory that must not be relabelled.
//
// Only the directory itself and its immediate parents match: `/var/lib` is on
// the list, but `/var/lib/myapp` is a perfectly reasonable thing to mount, and
// flagging it would make the rule useless.
func systemPathFor(source string) (systemPath, bool) {
	clean := strings.TrimRight(source, "/")
	if clean == "" {
		clean = "/"
	}
	for _, sp := range systemPaths {
		if clean == sp.Path {
			return sp, true
		}
	}
	return systemPath{}, false
}

// withOption renders a mount with an option added.
func withOption(m ir.Mount, option string) string {
	options := append(append([]string{}, m.Options...), option)
	return renderMountValue(m, options)
}

// stripOption returns a copy of a mount without the named option.
func stripOption(m ir.Mount, option string) ir.Mount {
	var kept []string
	for _, o := range m.Options {
		if o != option {
			kept = append(kept, o)
		}
	}
	m.Options = kept
	return m
}

// renderMountValue rebuilds a `Volume=` value from its parts.
func renderMountValue(m ir.Mount, options []string) string {
	var parts []string
	if m.Source != "" {
		parts = append(parts, m.Source)
	}
	parts = append(parts, m.Destination)
	value := strings.Join(parts, ":")
	if len(options) > 0 {
		value += ":" + strings.Join(options, ",")
	}
	return value
}
