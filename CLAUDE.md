# QuadDoc — Agent Guide

QuadDoc (`quaddoc`) converts docker-compose projects into Podman Quadlet units and
audits the result against a rule engine encoding real-world failure modes:
SELinux labelling, rootless UID/GID mapping, healthcheck semantics, network
translation.

Read `SPEC.md` for the full specification.

## Build and test

```sh
go build ./...          # build everything
go test ./...           # run all tests
go run ./cmd/quaddoc    # run the CLI
```

Golden files are refreshed with `go test ./... -update`.

## Project conventions

- **British English** throughout: prose, comments, doc strings, findings text.
  American spellings appear only where an external identifier demands it
  (`SELinux` labelling options, `color` in third-party APIs).
- **Rules cite their basis.** Every rule's doc string names the Podman, systemd,
  or SELinux documentation it encodes, and the versions it applies to. No
  folklore without a source.
- **Adding a rule is a single-file affair**: rule struct + registration + tests
  in one file under `internal/rules/`. The doc metadata renders the `quaddoc
  rules` reference page, so there is no separate docs step.
- **No shelling out** to `podman` in the core path. Host context reads files
  (`/sys/fs/selinux/enforce`, `/proc/self/mountinfo`, `/etc/subuid`), never
  subprocesses.
- **`--fix` is conservative.** Only provably semantics-preserving remediations
  get a fix; everything else is explain-only.
- Findings must be actionable: a copy-pasteable remediation, or an explicit
  "no mechanical fix — here is the decision you must make".

## Agent skills

### Issue tracker

Issues live as GitHub issues in `MatrixMagician/QuadDoc`, managed with the `gh`
CLI. See `docs/agents/issue-tracker.md`.

### Triage labels

The five canonical triage roles, each label string equal to its name. See
`docs/agents/triage-labels.md`.

### Domain docs

Single-context: `CONTEXT.md` at the root plus `docs/adr/`. See
`docs/agents/domain.md`.
