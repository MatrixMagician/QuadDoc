# QuadDoc

Convert docker-compose projects into Podman Quadlet units, and **audit the
result**.

`podlet` already does mechanical compose-to-Quadlet conversion. What QuadDoc
adds is a rule engine that encodes the failure modes that cost real debugging
hours and that no other tool checks: SELinux bind-mount labelling, rootless
UID/GID mapping, group-lookup pitfalls, healthcheck semantic drift, named-volume
ownership, and network translation.

Every rule cites the Podman, systemd, or SELinux documentation it encodes. Rules
that could not be justified from a source were reworded or dropped, and one from
the original specification was found to be **factually wrong** and rewritten
(see [the spec review](docs/spec-review.md)).

Single static Go binary. No dependency on podman being installed: host-context
checks degrade gracefully, and nothing shells out.

---

## The problem, in one example

Here is a perfectly ordinary compose file:

```yaml
services:
  web:
    image: docker.io/library/nginx:1.27
    ports: ["8080:80"]
    volumes:
      - ./site:/usr/share/nginx/html:ro
      - ./certs:/etc/nginx/certs
    depends_on:
      db: { condition: service_healthy }
    restart: unless-stopped

  db:
    image: docker.io/library/postgres:16
    volumes:
      - pgdata:/var/lib/postgresql/data
      - ./certs:/etc/postgresql/certs:ro
    environment:
      POSTGRES_PASSWORD: hunter2
    healthcheck:
      test: ["CMD", "pg_isready", "-U", "postgres"]
      start_period: 30s

volumes:
  pgdata:
```

Convert it:

```console
$ quaddoc convert compose.yaml --out units/
Wrote 6 units to units/
warning: depends_on db used condition: service_healthy, which systemd ordering
         cannot express; see the comment in the generated unit
note:    compose used `restart: unless-stopped`, which systemd cannot express
         exactly...
```

Then audit it:

```console
$ quaddoc lint units/
units/db.container
  warning:10 QD041 POSTGRES_PASSWORD= holds a literal credential in the unit file
    Move the value into a Podman secret and reference it:

        printf '%s' "$VALUE" | podman secret create postgres_password -

    then in the unit:

        Secret=postgres_password,type=env,target=POSTGRES_PASSWORD

  error:23 QD001 bind mount .../certs has no SELinux relabelling option, so on an
                 enforcing system the container would be denied access
    Add :z to the mount, mounted by 2 units, so a shared label is required;
    a private :Z would let them overwrite each other's categories:

        Volume=.../certs:/etc/postgresql/certs:ro,z

  warning QD020 web is ordered after db, but systemd ordering waits for the
                container to start, not to become ready

Found 3 errors, 4 warnings.
```

Note what the third finding did. `./certs` is mounted by **two** services, so it
needs the shared label `:z`; `./site` is mounted by one, so it gets the private
`:Z`. That distinction is invisible to a per-file linter, and getting it wrong
gives you containers that work individually and fail together, in an order that
depends on which one restarted last.

Fix the mechanical ones:

```console
$ quaddoc fix units/ --write
updated units/db.container (QD001)
updated units/web.container (QD001)

4 finding(s) have no mechanical fix and need a decision from you:
  QD020 Ordering does not wait for a dependency to become healthy (2)
  QD041 Credential passed as an environment value in the unit file (2)
```

The rest are left alone deliberately. Moving a password into a secret and
deciding whether a healthcheck gate is worth adding are decisions, not
transformations.

---

## Install

Download a static binary from the
[releases page](https://github.com/MatrixMagician/QuadDoc/releases), or:

```sh
VERSION=0.1.1
ARCH=$(uname -m | sed 's/x86_64/amd64/; s/aarch64/arm64/')
BASE=https://github.com/MatrixMagician/QuadDoc/releases/download/v${VERSION}

curl -fsSLO ${BASE}/quaddoc_${VERSION}_linux_${ARCH}.tar.gz
curl -fsSLO ${BASE}/checksums.txt
sha256sum --check --ignore-missing checksums.txt

tar xzf quaddoc_${VERSION}_linux_${ARCH}.tar.gz quaddoc
install -m755 quaddoc ~/.local/bin/quaddoc
```

The binaries are statically linked with CGO disabled, so they run on any Linux
distribution regardless of its libc. Nothing is needed at runtime, not even
podman.

From source, if you have Go:

```sh
go install github.com/MatrixMagician/quaddoc/cmd/quaddoc@latest
```

Either way, check the install with `quaddoc doctor`, which reports what it
detected about your system and how many rules it is carrying.

## Usage

```
quaddoc convert <compose.yaml> [--out units/] [--pod]
quaddoc lint <path...> [--host-context[=dir]] [--json|--sarif] [--explain]
quaddoc fix <path...> [--rule QD001,...] [--write]
quaddoc capture-context [--out ctx/]
quaddoc doctor
quaddoc rules [QD###] [--markdown]
```

Exit codes are CI-friendly: `0` clean, `1` warnings only, `2` any error.

### Host-aware mode

By default QuadDoc reasons from the units alone and words its findings as
possibilities. With `--host-context=live` it consults the system and upgrades
them to confirmed:

```console
$ quaddoc lint units/                       # "would be denied access"
$ quaddoc lint --host-context=live units/   # "SELinux is enforcing, so will be denied"
```

It reads files only, never subprocesses: `/sys/fs/selinux/enforce`,
`/proc/self/mountinfo`, `/etc/subuid`, `/etc/subgid`, and the port sysctl.

### Capture and replay

Because the context is only files, it can be captured on one machine and
replayed on another. Capture on the machine where something is wrong, lint on
your own:

```console
$ quaddoc capture-context --out ctx/       # on the broken machine
$ quaddoc lint --host-context=ctx/ units/  # anywhere
```

Replay is the same code as live, pointed at a directory, so the two cannot
drift. A capture records unit *names* only, never their contents, since units
carry secrets.

### CI

```yaml
- run: quaddoc lint --sarif units/ > quaddoc.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: quaddoc.sarif
```

### Configuration

`.quaddoc.toml`, searched upwards from the linted path:

```toml
[rules]
QD001 = "warning"   # we relabel out of band
QD040 = "off"
```

Or inline, where the reason is **mandatory**:

```ini
# quaddoc: disable=QD001 this path is labelled at mount time via fstab
```

A directive without a reason suppresses nothing and is reported. A suppression
whose justification has been lost is indistinguishable from a bug someone gave
up on.

## Rules

19 rules across five families. See the [full reference](docs/rules.md), or
`quaddoc rules QD001` for one.

| Family | Rules |
| --- | --- |
| SELinux | QD001 missing relabel, QD002 `:Z` on a shared source, QD003 relabelling a filesystem that cannot hold labels, QD004 relabelling a system directory |
| Rootless UID/GID | QD010 bind ownership mismatch, QD011 named group in `GroupAdd=`, QD012 volume chown, QD013 ID outside the subordinate range |
| Lifecycle | QD020 ordering is not a readiness gate, QD021 `unless-stopped`, QD022 missing `[Install]`, QD023 unhonoured `[Install]` key |
| Networking | QD030 no shared network, QD031 privileged port, QD032 name collision |
| Hygiene | QD040 `AutoUpdate=registry` with an unqualified image, QD041 credential in the unit, QD042 unrecognised key |

Adding a rule is a single-file affair: the struct, its registration, its
documentation, and its tests live together, and the same metadata renders the
reference page. `Register` panics on a rule with no citation, so "no folklore" is
structural rather than a convention.

## Works with podlet

podlet emits ordinary Quadlet units, so `quaddoc lint` audits its output with no
special handling. See [ADR-0003](docs/adr/0003-podlet-compatibility.md).

## How it is tested

The acceptance test for conversion is Podman's own Quadlet generator, not a
golden file:

```sh
QUADLET_UNIT_DIRS=units/ /usr/libexec/podman/quadlet -dryrun -user
```

Generated units, and fixed units, must both pass it. The test skips when the
generator is absent, so CI without podman still runs.

Beyond that: round-trip tests prove the parser reproduces a file byte for byte,
idempotence tests prove fixing twice equals fixing once, and the SELinux fixture
matrix covers enforcing, permissive, and absent.

Reference platform: Fedora, SELinux enforcing, rootless Podman ≥ 5.0, systemd
user units. Minimum Podman 5.0 ([ADR-0002](docs/adr/0002-minimum-podman-version.md)).

## Documentation

- [Rule reference](docs/rules.md) — generated from rule metadata
- [Specification](SPEC.md) and [review](docs/spec-review.md)
- [Architecture decisions](docs/adr/)
- [Domain vocabulary](CONTEXT.md)

## Licence

Apache 2.0. See [LICENSE](LICENSE).
