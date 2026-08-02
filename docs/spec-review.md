# SPEC.md review — QuadDoc v0.1

**Reviewer:** implementing agent
**Date:** 2026-08-02
**Method:** every load-bearing factual claim in the spec was checked against
`podman-systemd.unit(5)` and `podman-run(1)` as installed, and — where the claim
was about runtime behaviour — reproduced against live Podman 5.8.4 on a Fedora
box with SELinux enforcing and rootless Podman.

Verdict: **the spec is sound and worth building.** The differentiator is real,
the architecture is right, and the milestone ordering works. Four findings need
resolving before or during implementation; one rule is factually wrong as
written and must be restated. Details below.

---

## Reference environment

| Property | Value |
| --- | --- |
| Podman | 5.8.4 |
| Go | 1.26.2 |
| SELinux | Enforcing (`/sys/fs/selinux/enforce` = `1`) |
| Rootless | yes (`podman info` → `Rootless: true`) |
| Network backend | netavark |
| subuid/subgid | `oliverh:524288:65536` |
| `net.ipv4.ip_unprivileged_port_start` | 1024 |

---

## Claims verified as correct

**Quadlet key names.** Every key the spec names exists in `podman-systemd.unit(5)`
for Podman 5.8.4, with the semantics the spec assumes:

- `HealthStartPeriod=` — exists, maps to `--health-start-period`.
- `Notify=` — exists, and critically **`Notify=healthy` is a documented value**:
  "setting Notify to healthy will postpone startup notifications until such time
  as the container is marked healthy". QD020's recommendation is well-founded,
  not folklore. It requires `HealthCmd=` to be set, which QD020 must check.
- `GroupAdd=` — exists, "Also supports the keep-groups special flag". QD011's
  remediation is correct.
- `AutoUpdate=` — exists; `registry` "Requires a fully-qualified image reference
  ... to be used to create the container. This enforcement is necessary to know
  which image to actually check and pull." QD040 is exactly right, and the man
  page wording is a citable basis.
- `Secret=`, `User=`, `UserNS=`, `Volume=`, `Network=`, `PublishPort=`, `Pod=` —
  all present as assumed.

**Unit-type sections.** `[Container]`, `[Pod]`, `[Kube]`, `[Network]`,
`[Volume]`, `[Build]`, `[Image]`, `[Artifact]`. The spec's v1 scope
(`.container`, `.volume`, `.network`, `.pod`) is a coherent subset, and the
non-goal of excluding `.kube` matches a real section boundary.

**QD022 (missing `[Install]`).** Confirmed: "The services created by Podman are
considered transient by systemd, which means ... it is not possible to
`systemctl enable` them". The generator applies `[Install]` at generation time.
Only `Alias`, `WantedBy`, `RequiredBy`, `UpheldBy` are supported — QuadDoc should
flag *other* `[Install]` keys as silently ignored, which the spec does not
currently mention.

**QD030 (service-name DNS).** Verified empirically, and it is stronger than the
spec claims. The default `podman` network reports `"dns_enabled": false`. So
containers on the default network cannot resolve each other by name **at all** —
this is not a subtle degradation, it is a hard failure. `error` severity is
correct. Sibling-name resolution requires a user-defined network, which is what
a `.network` unit creates.

**QD001 (`:Z` relabelling).** Reproduced end to end. A bind source labelled
`unconfined_u:object_r:user_tmp_t:s0` was inaccessible from inside a container;
adding `:Z` relabelled it to `system_u:object_r:container_file_t:s0:c235,c710`
and the write succeeded. The rule catches a genuine, reproducible failure.

**QD031 (low ports rootless).** `net.ipv4.ip_unprivileged_port_start = 1024` on
the reference box, so ports below 1024 do fail rootless by default. Note the
sysctl is the *threshold*: the check is `port < value-of-sysctl`, and in
host-context mode QuadDoc should read the live value rather than hardcode 1024,
since administrators commonly lower it to 80.

---

## Findings

### F1 — QD012 is factually wrong as written (must fix before M3)

The spec says: *"named volume first-use ownership: image runs as non-root but no
`U`/chown strategy for the volume → warning."*

This is **not** how Podman behaves. Reproduced:

```
$ podman volume create qdtest
$ podman run --rm --user 1234:1234 -v qdtest:/data alpine ls -ldn /data
drwxr-xr-x 1 1234 1234 0 /data          # ← already owned correctly
```

Podman automatically chowns a named volume's mount point on first use.
`podman-run(1)` documents the conditions: the volume has `NeedsChown` set, is
empty or not yet copied-up, is not on an external driver, and the driver is not
`image`. So the spec's stated trigger produces a **false positive** — the most
damaging kind of finding for a linter whose entire value proposition is trust.

The real failure mode is the *negation* of those conditions, and it reproduces:

```
$ podman volume create qdpre
$ podman run --rm            -v qdpre:/data alpine touch /data/seed   # root populates it
$ podman run --rm --user 1234:1234 -v qdpre:/data alpine touch /data/y
touch: /data/y: Permission denied                                     # ← now it breaks
```

Once a volume has been populated, auto-chown no longer applies and a later
non-root container is denied. A local-driver volume with `type=none,o=bind` also
skips the useful path — the host directory keeps its own ownership (observed as
`525521:525521`, the subuid-mapped owner) and writes fail.

**Restate QD012 as:** a named volume is mounted by a container running as
non-root *and* the volume is shared with, or previously initialised by, a
container running as root, *or* the volume is a `local` driver volume with
`Device=`/`Options=bind` (a bind masquerading as a named volume) — because in
both cases first-use auto-chown does not save you. Severity warning, remediation
`:U` with the man page's own caveat that chowning walks every inode and can
delay start on large volumes.

This one rule justifies the review: shipped as specified it would have fired on
the common, correct case.

### F2 — the acceptance criterion "`podman quadlet --dryrun`-equivalent" needs correcting (M2)

`podman quadlet` in 5.8.4 is a *management* command — `install`, `list`, `print`,
`rm`. It has no `--dryrun`. The spec's parenthetical "(or documented manual
validation where CI lacks podman)" suggests the author was unsure this existed.

It does exist, just elsewhere. The generator binary at
`/usr/libexec/podman/quadlet` accepts `-dryrun -user`, and honours the
`QUADLET_UNIT_DIRS` environment variable to scope it to a directory:

```sh
QUADLET_UNIT_DIRS=/path/to/units /usr/libexec/podman/quadlet -dryrun -user
```

Verified: this prints the generated `.service` for units in that directory only,
and exits non-zero on malformed input. This is a genuine oracle and should be
wired into the test suite as a skip-if-absent integration test — the best
possible validation of M2, far better than golden files alone. Update the
acceptance criterion to name the real command.

### F3 — QD002 and QD001 can contradict each other; the shared-source analysis needs a defined precedence (M3)

QD001 says pick `:z` vs `:Z` by whether the source appears in multiple units.
QD002 errors on `:Z` for a source used by ≥ 2 units. So for a shared source both
rules engage the same fact, and a naive implementation reports twice for one
problem. Worse, `--fix` for QD001 could write `:Z` on a source that QD002 then
errors on.

Define it once in the IR: compute a project-wide *source-usage map* before any
rule runs, and let both rules read it. QD001 fires only when there is no label
option at all; QD002 fires only when `:Z` is present on a shared source. They
become mutually exclusive by construction. This also settles the spec's own
caveat that the analysis "works across a whole project directory, not per-file"
— it means rules cannot be pure functions of a single unit, and the rule
interface must therefore take a *project* plus the unit under test. Worth
deciding at M1, when the interface is defined, not at M3 when it is expensive to
change.

### F4 — three claims in the catalogue still need a citation before they ship

The spec's own guidance says "Do not encode folklore without a source". These
three are the ones I could not fully close from the installed documentation:

- **QD003** (relabelling on NFS/CIFS/FUSE, `context=` mount options). The
  direction is right, but the specific filesystem list and the recommended
  `context=` syntax want a citation to the SELinux or mount documentation, and
  the check should be driven by the filesystem type read from
  `/proc/self/mountinfo` rather than a hardcoded path pattern.
- **QD004** (`:Z` on system paths). Correct and important — relabelling `/home`
  or `/var/lib` recursively is genuinely destructive — but "must never" needs the
  path list pinned down and justified rather than left to taste. Suggest a small
  deny-list with a rationale per entry, and lean towards erring on the side of
  including a path.
- **QD042** (version key table). This is the highest-maintenance rule in the
  catalogue and the spec does not say how the table is produced. Generating it
  from the man page or from Podman's own source at release time is sustainable;
  hand-maintaining it is not. Consider deferring QD042 past v1 rather than
  shipping a table that silently rots.

---

## Smaller observations

- **`[Install]` key filtering.** Only four keys are honoured (F-verified above).
  A unit with `[Install] RequiredBy=` is fine; one with, say, `Also=` is silently
  dropped. Cheap rule, real bug, worth adding to the catalogue.
- **QD021 (`unless-stopped`).** Correct that systemd has no exact equivalent. The
  distinction is that `unless-stopped` survives a daemon restart but respects a
  manual stop, whereas systemd's `Restart=always` is orthogonal to enablement —
  the closest honest answer is `Restart=always` plus `[Install]`, which pairs
  this rule with QD022. Say so in the finding.
- **Rootless `.volume` naming.** Quadlet prefixes named volumes with `systemd-`
  (`ollama.volume` → volume `systemd-ollama`), and `.network` likewise. Any rule
  or fix that reasons about actual volume/network names, and QD032's collision
  check in particular, must apply that prefix or it will compare the wrong
  strings.
- **British English.** The spec mandates it, but the domain is full of
  American-spelled identifiers (`labeling` in SELinux contexts, `--label`). Keep
  British English in prose and rule text; never rewrite an identifier.

---

## Open questions from §9 — recommended resolutions

Recorded as ADRs in `docs/adr/`:

1. **Containers + shared `.network` by default, `--pod` opt-in.** Agrees with the
   spec's leaning. Reinforced by F-verified QD030: the shared `.network` is
   required for DNS anyway, so it is not merely a default, it is the only
   translation that preserves compose semantics. (ADR-0001)
2. **Minimum Podman 5.0.** Agrees with the spec's leaning, with the QD042 caveat
   in F4 — record the minimum, defer the delta table. (ADR-0002)
3. **Accept podlet output as a tested path.** Cheap: podlet emits ordinary
   Quadlet units, so if the parser is fixture-tested against real units it
   already handles them. Worth a fixture, not worth special-casing. (ADR-0003)
4. **AppArmor in v2.** Agrees with the spec's leaning. Ship the SELinux-absent
   downgrade behaviour now, which M3's fixture matrix already requires.
   (ADR-0004)

---

## Recommendation

Build it, in the spec's milestone order, with these amendments:

1. Restate QD012 per F1 before implementing M3.
2. Correct M2's acceptance criterion to `/usr/libexec/podman/quadlet -dryrun`
   with `QUADLET_UNIT_DIRS`, and wire it in as a skip-if-absent test.
3. Make the rule interface take a project, not a unit, at M1 (F3).
4. Either cite or defer QD003/QD004/QD042 (F4); recommend deferring QD042.
