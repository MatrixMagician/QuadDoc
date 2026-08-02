# Releasing QuadDoc

Releases are built by the `Release` workflow, not on a maintainer's machine.
Tagging and pushing is the whole procedure.

```sh
# From a clean main with CI green:
git tag -a v0.2.0 -m "QuadDoc v0.2.0

<what changed and why it matters to someone deciding whether to upgrade>"

git push origin v0.2.0
```

The workflow then builds static binaries for linux/amd64 and linux/arm64,
generates checksums, writes the release notes, and publishes.

## Do not publish by hand

Running `goreleaser release` locally for a tag the workflow is also handling
races it. Whichever finishes second fails with `already_exists` on every asset,
and the release is left with binaries from whichever won, which may not be the
ones the tag describes. That happened for v0.1.0 and is the reason this file
exists.

If you need to inspect what a release *would* contain, build without
publishing:

```sh
goreleaser release --clean --skip=publish
ls dist/
```

## Before tagging

The workflow checks the rule reference is current, and CI covers the rest, but
these are worth running locally because they are slow to discover in CI:

```sh
go test -count=1 ./...              # -count=1 matters; see below
bash scripts/mutation-check.sh      # every mutation should be caught
python3 scripts/check-citations.py  # every quote verified against its man page
```

`-count=1` is not optional. Go caches test results, and a cached pass will hide
a break you have just introduced. An earlier version of the mutation script
omitted it and reported six false gaps.

## What the version number means

The version is stamped into the binary with `-ldflags -X main.version`, so
`quaddoc version` reports the tag rather than `dev`. A binary built with plain
`go build` reports `dev`, which is how you can tell a local build from a
released one.

## Choosing a version

- **Patch** for fixes that change no rule's behaviour: portability, tests, CI,
  documentation.
- **Minor** for new rules, new output formats, or new subcommands. Adding a
  rule can fail a build that previously passed, so it is never a patch.
- **Major** for changes to the JSON schema, the exit-code contract, or the
  meaning of an existing rule. These are what people script against.

## After releasing

Update the `VERSION=` line in the README's install example, which is what
people copy.

Check the published artefacts actually work, rather than assuming:

```sh
cd "$(mktemp -d)"
VERSION=0.2.0
ARCH=$(uname -m | sed 's/x86_64/amd64/; s/aarch64/arm64/')
BASE=https://github.com/MatrixMagician/QuadDoc/releases/download/v${VERSION}

curl -fsSLO ${BASE}/quaddoc_${VERSION}_linux_${ARCH}.tar.gz
curl -fsSLO ${BASE}/checksums.txt
sha256sum --check --ignore-missing checksums.txt

tar xzf quaddoc_${VERSION}_linux_${ARCH}.tar.gz quaddoc
./quaddoc version   # should print the tag, not "dev"
./quaddoc doctor
```
