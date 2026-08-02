# QuadDoc — Convert, Lint, and Diagnose Podman Quadlets

**Specification v0.1 — for implementation via Claude Code / agentic harness**

---

## 1. Overview

QuadDoc (binary: `quaddoc`) converts docker-compose projects into Podman Quadlet units **and audits the result** — encoding the failure modes that cost real debugging hours but that no existing tool checks: SELinux bind-mount labelling, rootless UID/GID mapping collisions, group-lookup pitfalls, healthcheck semantic drift, named-volume ownership, network and dependency-ordering translation. It also lints existing hand-written Quadlet files, making it useful beyond migration.

`podlet` already does mechanical compose→Quadlet conversion; the differentiator here is the **rule engine**: conversion output (or pre-existing units) passes through a battery of context-aware checks, each with an explanation, a severity, and a concrete fix — `audit2allow` energy, but actually pleasant.

Reference platform: Fedora (SELinux enforcing), rootless Podman ≥ 5.x, systemd user units. Must also behave sensibly on permissive/AppArmor systems (SELinux rules downgrade to notes).

---

## 2. Goals and Non-Goals

### Goals
1. **Convert:** parse compose files (compose-spec) and emit `.container`, `.volume`, `.network`, and `.pod` Quadlet units, preserving intent and annotating every non-obvious translation decision as a comment in the generated unit.
2. **Lint:** run a rule engine over generated *or existing* Quadlet units (and optionally the live host context) producing findings with rule ID, severity (error/warning/note), explanation, and remediation snippet.
3. **Host-aware mode (optional flag):** with `--host-context`, consult the local system — SELinux mode, filesystem labels/mount options of bind-mount sources, subuid/subgid ranges, existing unit name collisions — to upgrade findings from "possible" to "confirmed".
4. Output formats: human (grouped, coloured), `--json` (stable schema), `--sarif` (CI/code-review integration).
5. `--fix` for mechanically safe remediations (e.g. adding `:Z`/`:z` where unambiguous), always as a diff preview first.
6. Single static Go binary, no runtime dependency on podman being installed (host-context checks degrade gracefully).

### Non-Goals (v1)
- Not a general compose feature-completeness port (build:, profiles:, extends: → explicit "unsupported, here's why" findings rather than partial translation).
- No Kubernetes YAML / `.kube` unit support (v2 candidate).
- No daemon; no applying changes to the system (generates files and diffs only).
- Not an SELinux policy generator — it fixes *labels and options*, and where a genuine policy issue exists it says so and points at the right tooling.

---

## 3. Rule Catalogue (initial set — the heart of the project)

Each rule: `QD###` ID, applies-to (conversion/existing/both), severity default, rationale, remediation. Seed set, drawn from documented real-world failure modes:

**SELinux**
- `QD001` bind mount without `:Z`/`:z` on an SELinux-enforcing target → error. Distinguish shared (`:z`) vs private (`:Z`) by whether the source appears in multiple units in the project.
- `QD002` `:Z` on a shared source used by ≥ 2 units → error (relabel wars).
- `QD003` bind mount source on a filesystem where relabelling is wrong or ineffective (NFS/CIFS/FUSE, or paths needing `context=` mount options instead — e.g. foreign-distro btrfs subvolumes) → warning with `context=` guidance. Host-context mode confirms via `/proc/self/mountinfo`.
- `QD004` `:Z` on system paths (`/home` root, `/var/lib` shared dirs) that must never be container-relabelled → error.

**Rootless UID/GID**
- `QD010` `User=`/`--user` inside container combined with bind mounts owned by the host user → warning explaining the double-mapping (host UID → intermediate → container UID) with `--userns=keep-id` / `:U` options compared.
- `QD011` `--group-add` with a named group in rootless mode → error; groups resolve inside the container; recommend `--group-add=keep-groups` for host-group passthrough (documented Podman semantics).
- `QD012` named volume first-use ownership: image runs as non-root but no `U`/chown strategy for the volume → warning.
- `QD013` compose `user:` numeric IDs outside the available subuid/subgid range (host-context mode) → error.

**Healthchecks & lifecycle**
- `QD020` compose `healthcheck.start_period` translated without `HealthStartPeriod=`, or `depends_on: condition: service_healthy` translated to plain `After=`/`Wants=` → warning: systemd ordering ≠ health gating; recommend `Notify=healthy` (sdnotify) pattern where the workload supports it, or explicit comment acknowledging the gap.
- `QD021` `restart: always|unless-stopped` mapping to `Restart=` — flag `unless-stopped` as having no exact systemd equivalent; recommend `Restart=always` + explanation.
- `QD022` missing `[Install] WantedBy=default.target` (unit will never autostart) → error for services, note for one-shots.

**Networking & naming**
- `QD030` compose service-name DNS reliance without a shared `.network` unit → error (default Quadlet networking won't resolve sibling names); generate the `.network` and wire `Network=`.
- `QD031` published ports < 1024 rootless without `net.ipv4.ip_unprivileged_port_start` note → warning.
- `QD032` container/unit name collisions with existing units (host-context mode) → error.

**Hygiene**
- `QD040` `latest`/floating tags with `AutoUpdate=registry` enabled → warning pairing (auto-update needs fully-qualified image refs; flag short names lacking a registry).
- `QD041` secrets passed as environment values in the unit file → warning; recommend `Secret=` / podman secrets.
- `QD042` deprecated Quadlet keys or keys unknown to the targeted Podman version (versioned key table) → warning.

The rule engine must make adding a rule a single-file affair: rule struct + tests + doc string that becomes the generated rules reference page.

---

## 4. Architecture

```
 compose.yaml ──▶ parser (compose-go) ──▶ IR ──▶ generator ──▶ units/
 existing *.container ─▶ quadlet parser ─▶ IR ────────────────────┘
                                          │
                                    rule engine ◀── host context (optional)
                                          │
                              findings ──▶ render: human | json | sarif
                                          │
                                        --fix ──▶ diff preview ──▶ apply
```

- **IR:** a normalised model of units (options, mounts, users, networks, dependencies) so rules never care whether input was compose or native Quadlet.
- **Parsers:** `compose-spec/compose-go` for compose; own INI-with-Quadlet-semantics parser for unit files (systemd INI quirks: repeated keys, line continuations, `#`/`;` comments) — keep it small and fixture-tested against real units.
- **Host context:** interface with two implementations — live (reads `/sys/fs/selinux/enforce`, `/proc/self/mountinfo`, `/etc/subuid`, `getenforce`-free) and fixture (for tests and for `--host-context=dir` replay of a captured context, which doubles as a support/debugging workflow: capture on the broken machine, lint anywhere).

---

## 5. CLI Design

```
quaddoc convert <compose.yaml> [--out units/] [--pod|--containers]
quaddoc lint <path…> [--host-context[=captured-dir]] [--json|--sarif]
quaddoc fix <path…> [--rule QD001,…] [--write]     # diff preview by default
quaddoc capture-context [--out ctx/]                # for replay linting
quaddoc rules [QD###]                               # rendered rule docs
quaddoc doctor                                      # self-check: podman/selinux versions detected
```

Exit codes: 0 clean, 1 warnings only (configurable gate), 2 errors — CI-friendly; `.quaddoc.toml` for per-project rule enables/severity overrides with inline `# quaddoc: disable=QD001 reason…` escapes (reason mandatory).

---

## 6. Milestones and Acceptance Criteria

**M1 — IR + Quadlet parser + lint skeleton with 3 rules**
✔ Parses fixture `.container` files (including repeated keys and continuations) into IR round-trippably; `QD022`, `QD040`, `QD041` implemented; human + JSON output; golden-file tests for findings.

**M2 — Compose conversion**
✔ Converts a realistic multi-service fixture (web + db + named volumes + custom network + healthchecks) into units that pass `podman quadlet --dryrun`-equivalent validation in CI (or documented manual validation where CI lacks podman); every non-trivial mapping annotated in-file; unsupported compose keys produce findings, never silent drops.

**M3 — SELinux + UID/GID rule sets**
✔ QD001–QD013 implemented with table-driven tests covering enforcing/permissive/absent SELinux fixtures; the `:z` vs `:Z` shared-source analysis works across a whole project directory, not per-file.

**M4 — Host-context mode + capture/replay**
✔ Live context correctly detected on a Fedora reference box; `capture-context` + replay produces identical findings to live on that box; all context-dependent rules downgrade correctly with no context.

**M5 — Fix engine + SARIF + rules docs**
✔ `--fix` for QD001/QD030/QD022 with diff preview and idempotence tests (fix twice = fix once); SARIF validates against schema; `rules` subcommand output generated from rule metadata and published as docs.

**M6 — Release**
✔ goreleaser static binaries; README with a worked before/after migration of the fixture project; rule reference published; COPR spec stretch goal.

---

## 7. Repository Layout

```
quaddoc/
├── SPEC.md / CLAUDE.md
├── cmd/quaddoc/main.go
├── internal/
│   ├── ir/
│   ├── parse/{compose/, quadlet/}
│   ├── generate/
│   ├── rules/            # one file per rule family, registry pattern
│   ├── hostctx/{live/, fixture/}
│   ├── fix/
│   └── output/{human/, json/, sarif/}
├── testdata/             # compose fixtures, unit fixtures, captured contexts
└── docs/decisions/
```

---

## 8. Guidance for the Implementing Agent

- Rules must cite their basis: each rule's doc string links to the Podman/Quadlet/SELinux documentation or documented behaviour it encodes. Where behaviour is version-dependent, say which versions. Do not encode folklore without a source.
- Verify current Quadlet key names and semantics against the installed podman-systemd.unit(5) documentation during M1 rather than assuming; the format evolves quickly.
- Findings must be actionable: every error/warning includes a copy-pasteable remediation or an explicit "no mechanical fix; here's the decision you must make".
- `--fix` is conservative: only rules whose remediation is provably semantics-preserving get fixes; everything else is explain-only.
- No shelling out to `podman` in the core path; host-context uses files, not subprocesses, wherever possible.
- British English throughout.

## 9. Open Questions (record in `docs/decisions/`)

1. Whether conversion targets one `.pod` unit vs sibling `.container` units by default (leaning: containers + shared `.network`, `--pod` opt-in).
2. Minimum supported Podman version (leaning: 5.0, with QD042's key table encoding deltas since).
3. Whether to embed podlet-compatibility (accept its output for lint-only users) as a tested path.
4. AppArmor-specific rules (Debian/Ubuntu hosts) in v1 or v2 (leaning v2; ship SELinux-downgrade behaviour now).
