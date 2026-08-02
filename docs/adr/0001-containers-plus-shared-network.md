# ADR-0001 — Conversion targets sibling `.container` units with a shared `.network`

**Status:** accepted
**Date:** 2026-08-02
**Resolves:** SPEC.md §9 open question 1

## Context

A compose project maps onto Quadlet in two plausible shapes: one `.pod` unit
containing every service, or one `.container` unit per service with a shared
`.network` unit joining them. The spec leaned towards the latter without
settling it.

During the spec review we established (see `docs/spec-review.md`) that Podman's
default network reports `dns_enabled: false`. Containers on it cannot resolve
each other by name at all. Compose, by contrast, guarantees that a service can
reach a sibling by its service name. So *some* user-defined network is not a
stylistic preference — it is the only way to preserve compose semantics.

## Decision

Convert each compose service to its own `.container` unit, and emit one
`.network` unit per compose network (plus a default project network when compose
declares none). Each container gets `Network=<project>.network`.

`--pod` remains available to emit a single `.pod` unit instead, for users who
want shared-namespace semantics.

## Consequences

- Sibling DNS works, matching compose.
- Units can be started, stopped, and restarted independently, which is the
  systemd-native shape and the reason to migrate at all.
- QD030 becomes a rule about a translation we already perform correctly, and
  applies mainly to hand-written units and podlet output.
- Under `--pod`, containers share a network namespace and reach each other on
  `localhost`; service-name DNS does not apply, so QD030 must not fire for pod
  members.
