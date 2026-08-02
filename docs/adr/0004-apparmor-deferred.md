# ADR-0004 — AppArmor-specific rules deferred to v2

**Status:** accepted
**Date:** 2026-08-02
**Resolves:** SPEC.md §9 open question 4

## Context

The reference platform is Fedora with SELinux enforcing. Debian and Ubuntu hosts
use AppArmor, where the SELinux rule family (QD001–QD004) does not apply and
where a different set of confinement failure modes exists.

## Decision

v1 ships **SELinux rules with correct downgrade behaviour** and no
AppArmor-specific rules.

When host context reports SELinux absent or permissive, SELinux-dependent rules
downgrade: `error` becomes `note` under permissive (the label is still wrong, it
just is not being enforced today, and enabling enforcing later will break the
container), and they are suppressed entirely when SELinux is absent from the
kernel.

Without host context, SELinux rules report at their default severity, worded as
possibilities rather than confirmations.

## Consequences

- A Debian user gets useful output — conversion, networking, healthcheck,
  hygiene, and rootless UID/GID rules all still apply — without noise about a
  security module they do not run.
- The downgrade ladder is a first-class part of the rule engine from M1, not an
  afterthought, because M3's fixture matrix (enforcing / permissive / absent)
  depends on it.
- AppArmor rules in v2 slot into the same mechanism as another confinement
  backend.
