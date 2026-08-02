# ADR-0003 — podlet output is a tested fixture, not a special-cased input

**Status:** accepted
**Date:** 2026-08-02
**Resolves:** SPEC.md §9 open question 3

## Context

`podlet` performs mechanical compose-to-Quadlet conversion. A natural user is
someone who already converted with podlet and wants QuadDoc's audit over the
result. The spec asked whether to embed podlet compatibility as a tested path.

## Decision

No special-casing. podlet emits ordinary Quadlet unit files, so the existing
Quadlet parser handles them by construction. We carry podlet-shaped units in
`testdata/` as parser fixtures to keep that honest, and say so in the README.

## Consequences

- `quaddoc lint` works on podlet output with no extra code.
- If podlet ever emits something our parser rejects, a fixture test catches it
  and the fix belongs in the parser — where it benefits hand-written units too.
- We take no dependency on podlet, and do not track its releases.
