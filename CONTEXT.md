# QuadDoc — Domain Context

The vocabulary this project uses. When naming things in code, tests, issues, or
findings text, use the term as defined here rather than a synonym.

## Core terms

**Unit** — a single Quadlet file (`.container`, `.volume`, `.network`, `.pod`)
and its parsed contents. Not "service": a unit *generates* a systemd service, and
conflating the two loses the distinction QD022 depends on.

**Project** — a set of units considered together, usually a directory. The
project, not the unit, is the subject a rule examines, because several rules
(QD001/QD002 shared-source analysis, QD030 network wiring, QD032 name collisions)
are only answerable across the whole set. See ADR-0001 and finding F3 of
`docs/spec-review.md`.

**IR** — the normalised model a project is parsed into, from either compose or
native Quadlet input. Rules read the IR and never learn which input produced it.
This is what makes "lint what you converted" and "lint what you hand-wrote" the
same code path.

**Rule** — a named check (`QD###`) over a project, producing zero or more
findings. A rule owns its identity, default severity, documentation, and
citation in one place; that metadata renders the `quaddoc rules` reference.

**Finding** — one reported problem: rule ID, severity, the unit and location it
concerns, an explanation, and a remediation. A finding without an actionable
remediation is a bug in the rule.

**Severity** — `error`, `warning`, or `note`. Drives the exit code: 2 for any
error, 1 for warnings only, 0 for clean.

**Host context** — observed facts about a live system: SELinux mode, mount
points and filesystem types, subuid/subgid ranges, existing unit names. Optional.
Rules that consult it must behave sensibly when it is absent.

**Confidence** — whether a finding is a *possibility* (no host context, reasoned
from the units alone) or *confirmed* (host context established the fact). The
same rule can produce either; the wording and sometimes the severity differ.

**Downgrade** — the lowering of a rule's severity because host context showed it
matters less here than in general: SELinux rules under a permissive kernel become
notes, and vanish entirely when SELinux is absent. See ADR-0004.

**Fix** — a mechanically applied remediation. Only rules whose remediation is
provably semantics-preserving have one. Fixes must be idempotent: applying twice
equals applying once.

**Capture** — a serialised host context, written on one machine and replayed on
another. Makes lint results reproducible, and doubles as a support workflow.

## Terms to avoid

- **"Service"** for a Quadlet file. Say *unit*. Reserve "service" for the
  generated systemd service, or for a compose service where the input is compose.
- **"Error"** as a generic word for a finding. A finding has a severity, and
  `error` is one of three.
- **"Container"** unqualified when you mean a `.container` unit. Say *unit* or
  *container unit*; "container" is the running thing.

## Naming quirks worth remembering

Quadlet prefixes the Podman objects it creates with `systemd-`: `web.volume`
creates a volume named `systemd-web`, and `app.network` a network named
`systemd-app`. Any rule reasoning about real object names, notably QD032's
collision check, must apply the prefix.
