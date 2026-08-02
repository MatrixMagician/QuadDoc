# QuadDoc rule reference

Generated from the rule metadata by `quaddoc rules --markdown`.
Every rule cites the documentation or observed behaviour it encodes.

| Rule | Severity | Fixable | Summary |
| --- | --- | --- | --- |
| [QD000](#qd000) | warning |  | Suppression directive gives no reason |
| [QD001](#qd001) | error | yes | Bind mount has no SELinux relabelling option |
| [QD002](#qd002) | error |  | Private label :Z used on a source shared between units |
| [QD003](#qd003) | warning |  | Relabelling is ineffective or wrong on this filesystem |
| [QD004](#qd004) | error |  | Relabelling a system directory would break the host |
| [QD010](#qd010) | warning |  | Container user and host bind mount ownership will not line up |
| [QD011](#qd011) | error |  | Named group in GroupAdd= will not resolve to the host group |
| [QD012](#qd012) | warning |  | Named volume will not be chowned for a non-root container |
| [QD013](#qd013) | error |  | Container UID or GID falls outside the available subordinate range |
| [QD020](#qd020) | warning |  | Ordering does not wait for a dependency to become healthy |
| [QD021](#qd021) | error |  | Restart policy has no exact systemd equivalent |
| [QD022](#qd022) | error | yes | Unit has no [Install] section and will never autostart |
| [QD023](#qd023) | warning |  | [Install] contains a key Quadlet does not honour |
| [QD030](#qd030) | error | yes | Sibling containers cannot resolve each other without a shared network |
| [QD031](#qd031) | warning |  | Published port is below the unprivileged threshold |
| [QD032](#qd032) | error |  | Unit name collides with an existing unit or Podman object |
| [QD040](#qd040) | warning |  | AutoUpdate=registry needs a fully-qualified image reference |
| [QD041](#qd041) | warning |  | Credential passed as an environment value in the unit file |
| [QD042](#qd042) | warning |  | Key is not recognised by Quadlet and will be ignored |

## QD000

**Suppression directive gives no reason**

- Default severity: `warning`

A `# quaddoc: disable=` comment without a reason is indistinguishable from a bug someone gave up on. The cost is paid later, by whoever finds it and cannot tell whether the justification still holds, so quaddoc ignores a directive with no reason and says so.

*Source: A project convention rather than an external one; see CLAUDE.md and SPEC.md section 5, which requires the reason.*

## QD001

**Bind mount has no SELinux relabelling option**

- Default severity: `error`
- Fixable by `quaddoc fix`
- Confirmed with `--host-context`; reported as a possibility without it

A bind-mounted host directory keeps whatever label it already had. Container processes run confined and are denied access to labels outside their type, so the mount appears as permission denied inside the container even though the Unix permissions look right. The :z and :Z options relabel the source to container_file_t.

*Source: podman-run(1), --volume: "The :Z option tells Podman to label the content with a private unshared label", ":z" for shared content. Reproduced on Podman 5.8.4 with SELinux enforcing: a source labelled user_tmp_t was denied; after :Z it became container_file_t:s0:c235,c710 and the write succeeded.*

## QD002

**Private label :Z used on a source shared between units**

- Default severity: `error`
- Confirmed with `--host-context`; reported as a possibility without it

The :Z option applies a label private to one container. When two containers both relabel the same source with :Z they overwrite each other's category set, so whichever started most recently works and the other is denied. The failure looks intermittent and follows restart order, which makes it painful to diagnose.

*Source: podman-run(1), --volume: "The Z option tells Podman to label the content with a private unshared label. Only the current container can use a private volume." Shared content is what :z is for.*

## QD003

**Relabelling is ineffective or wrong on this filesystem**

- Default severity: `warning`
- Confirmed with `--host-context`; reported as a possibility without it

Network and FUSE filesystems do not store SELinux labels per file. Relabelling them either fails outright or silently does nothing, and the container is denied anyway. Such filesystems take a whole-filesystem label through the context= mount option instead.

*Source: mount(8) and selinux(8): context= sets a single label for a whole filesystem and is the documented approach for filesystems that do not support extended attributes, such as NFS and CIFS. Confirmed from the filesystem type in /proc/self/mountinfo under host context.*

## QD004

**Relabelling a system directory would break the host**

- Default severity: `error`

Relabelling is recursive. Pointing it at a system directory rewrites the labels of files that confined services on the host depend on, and those services then fail. The damage outlives the container and is not undone by removing it: it takes a restorecon over the affected tree.

*Source: podman-run(1), --volume: "Note: Do not relabel system files and directories. Relabeling system content might cause other confined services on your machine to fail."*

## QD010

**Container user and host bind mount ownership will not line up**

- Default severity: `warning`

Rootless Podman maps container UIDs through the user's subordinate range, so UID 1000 inside the container is not UID 1000 on the host. A bind mount owned by the host user appears as owned by nobody inside the container, and writes are denied. Neither the container nor the host is misconfigured; the mapping simply does not do what people expect.

*Source: podman-run(1), --userns=keep-id: maps the current user's UID into the container so that host-owned files are accessible. podman-systemd.unit(5), UserNS= and Volume= :U.*

## QD011

**Named group in GroupAdd= will not resolve to the host group**

- Default severity: `error`

GroupAdd= resolves names against the container's /etc/group, not the host's. A host group name either does not exist in the image, so the unit fails to start, or exists with a different GID, so the container silently joins the wrong group. Neither is what the author meant by naming a host group.

*Source: podman-systemd.unit(5), GroupAdd=: "Also supports the keep-groups special flag." podman-run(1), --group-add: "keep-groups is a special flag that tells Podman to keep the supplementary group access ... Currently only available with the crun OCI runtime."*

## QD012

**Named volume will not be chowned for a non-root container**

- Default severity: `warning`

Podman chowns a named volume's mount point on first use, so the common case of a fresh volume and a non-root image needs no help. The failure is the exception: once a volume has been populated, or when it is a bind masquerading as a named volume, that automatic chown no longer applies and the non-root process is denied.

*Source: podman-run(1), "Chowning Volume Mounts": the chown occurs only when "The volume was not used yet (has NeedsChown set to true)", "The volume is empty or has not been copied up yet", the volume is not on an external driver, and the driver is not "image". Reproduced on Podman 5.8.4: a fresh volume was chowned to 1234:1234 automatically, while a volume first populated by root gave Permission denied to a later --user 1234 container.*

## QD013

**Container UID or GID falls outside the available subordinate range**

- Default severity: `error`
- Confirmed with `--host-context`; reported as a possibility without it

Rootless Podman can only map IDs within the ranges allocated to the user in /etc/subuid and /etc/subgid. An ID beyond the end of the range cannot be mapped, and the container fails to start with an error that names the ID but not the reason.

*Source: subuid(5) and subgid(5); podman-run(1), --uidmap. Rootless Podman maps container IDs through these ranges, so the largest usable ID is the range's size minus one.*

## QD020

**Ordering does not wait for a dependency to become healthy**

- Default severity: `warning`

systemd's After= orders one unit after another has *started*, which for a container means the moment Podman launched it, not the moment the process inside is ready to serve. A dependent container therefore starts against a database that is still initialising. Notify=healthy closes the gap by delaying the readiness notification until Podman marks the container healthy.

*Source: podman-systemd.unit(5), Notify=: "setting Notify to healthy will postpone startup notifications until such time as the container is marked healthy, as determined by Podman healthchecks. Note that this requires setting up a container healthcheck, see the HealthCmd option for more."*

## QD021

**Restart policy has no exact systemd equivalent**

- Default severity: `error`

compose's `unless-stopped` is not a systemd restart policy. systemd does not reject it: it logs a parse failure and carries on with no restart policy at all, so the container silently never restarts. The honest translation is Restart=always with an [Install] section, since systemd separates the restart policy from enablement.

*Source: systemd.service(5), Restart= lists the accepted values, which do not include unless-stopped. Verified with systemd-analyze verify on the generated service: "Failed to parse Restart=unless-stopped, ignoring: Invalid argument".*

## QD022

**Unit has no [Install] section and will never autostart**

- Default severity: `error`
- Fixable by `quaddoc fix`

Quadlet services are transient, so they cannot be enabled with systemctl. The generator applies the [Install] section at generation time instead. Without one the unit starts only when started by hand.

*Source: podman-systemd.unit(5), "Enabling unit files": services created by Podman are transient, "it is not possible to systemctl enable them in order for them to become automatically enabled on the next boot". The generator "manually applies the [Install] section ... in the same way systemctl enable does".*

## QD023

**[Install] contains a key Quadlet does not honour**

- Default severity: `warning`

Quadlet applies only Alias, WantedBy, RequiredBy, and UpheldBy from [Install]. Any other key is read and discarded without warning, so a unit can look correctly installed while doing nothing.

*Source: podman-systemd.unit(5), "Enabling unit files": "Currently, only the Alias, WantedBy, RequiredBy, and UpheldBy keys are supported."*

## QD030

**Sibling containers cannot resolve each other without a shared network**

- Default severity: `error`
- Fixable by `quaddoc fix`

Podman's default network has DNS disabled, so containers on it cannot resolve each other by name at all. This is not a degraded form of compose's behaviour, it is the absence of it: a container that expects to reach a sibling by service name fails with an unresolvable host.

*Source: Observed on Podman 5.8.4: `podman network inspect podman` reports "dns_enabled": false for the default network. podman-network-create(1) enables DNS for user-defined networks, which podman-systemd.unit(5) creates from a .network unit.*

## QD031

**Published port is below the unprivileged threshold**

- Default severity: `warning`
- Confirmed with `--host-context`; reported as a possibility without it

A rootless container cannot bind a host port below the kernel's unprivileged threshold, so the unit fails to start with a permission error that names the port but not the reason. The threshold is a sysctl, not a constant, and administrators commonly lower it.

*Source: net.ipv4.ip_unprivileged_port_start, documented in ip-sysctl.txt; read from the live system under host context rather than assumed. Observed as 1024 on the reference platform.*

## QD032

**Unit name collides with an existing unit or Podman object**

- Default severity: `error`
- Confirmed with `--host-context`; reported as a possibility without it

Quadlet prefixes the objects it creates with `systemd-`, so a name collision is not always obvious from the unit file. Two units resolving to the same object silently share it, and whichever starts last wins.

*Source: podman-systemd.unit(5), Volume=: "If SOURCE-VOLUME ends with .volume, a Podman named volume called systemd-$name is used". The same prefixing applies to networks. Verified on Podman 5.8.4: pg.volume created a volume named systemd-pg.*

## QD040

**AutoUpdate=registry needs a fully-qualified image reference**

- Default severity: `warning`

Auto-update has to know which image to check, which it cannot do from a short name that depends on registry search order, nor from a digest that never changes. A floating tag such as latest is also worth flagging: it works, but combined with auto-update it means the running version is whatever the registry served most recently.

*Source: podman-systemd.unit(5), AutoUpdate=: registry "Requires a fully-qualified image reference (e.g., quay.io/podman/stable:latest) to be used to create the container. This enforcement is necessary to know which image to actually check and pull." The Quadlet generator itself warns on short names (observed, Podman 5.8.4).*

## QD041

**Credential passed as an environment value in the unit file**

- Default severity: `warning`

A unit file is world-readable in the Quadlet search path and is usually committed to version control, so a credential in Environment= is exposed twice over. Podman secrets keep the value out of the unit and out of the container's environment listing.

*Source: podman-systemd.unit(5), Secret=: "Use a Podman secret in the container either as a file or an environment variable." Equivalent to podman-run(1) --secret.*

## QD042

**Key is not recognised by Quadlet and will be ignored**

- Default severity: `warning`

Quadlet reads the keys it knows and ignores the rest without complaint, so a typo'd key looks like configuration that simply does not work. This most often bites when a key is spelled as its podman flag (Volumes= for Volume=) or as the compose key it came from.

*Source: podman-systemd.unit(5) lists the keys each unit type accepts. The set is generated from the installed manual page by internal/rules/genkeys; see docs/adr/0002-minimum-podman-version.md for why per-version deltas are not attempted in v1.*

