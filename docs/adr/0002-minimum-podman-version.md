# ADR-0002 — Minimum supported Podman is 5.0; no version-delta key table in v1

**Status:** accepted
**Date:** 2026-08-02
**Resolves:** SPEC.md §9 open question 2, and finding F4 of `docs/spec-review.md`

## Context

The spec leaned towards Podman 5.0 as the floor, and proposed QD042 to warn about
keys unknown to the targeted Podman version, backed by a version-delta key table.

Quadlet's key surface moves quickly — 5.8 alone carries `.artifact` units and
several health keys absent from 5.0. A hand-maintained table encoding which key
arrived in which release is a standing maintenance cost, and one that fails
quietly: a stale table produces confident, wrong findings, which is worse for a
linter than producing none.

## Decision

Minimum supported Podman is **5.0**. Quadlet has been stable in shape since 4.4,
but 5.0 is where the rootless defaults this tool reasons about settled.

For v1, QuadDoc validates keys against a **single known-key set** derived from the
reference platform, and QD042 reports only *unknown* keys — keys in no released
Quadlet — rather than attempting per-version deltas. A key that exists but is too
new for the user's Podman is not flagged in v1.

When the delta table lands, it must be **generated** from Podman's own source or
manual pages at release time, never hand-maintained.

## Consequences

- QD042 ships narrower than specified but is always correct: a typo'd or
  removed key is caught, which is the common real-world case.
- Users on 5.0 running a unit that uses a 5.8 key get no warning from QuadDoc.
  Accepted for v1; documented in the rule text so the gap is explicit.
- The known-key set is a generated artefact, checked in, with the generator
  alongside it.
