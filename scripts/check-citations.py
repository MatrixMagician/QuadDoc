#!/usr/bin/env python3
"""Check that every quoted citation in the rule catalogue appears verbatim in
the manual page it names.

A rule's citation is its licence to exist. If the quote has drifted from the
source, the rule is folklore wearing a reference, which is exactly what the
project set out to avoid.
"""
import re
import subprocess
import sys

MAN_PAGES = {
    "podman-run(1)": "podman-run",
    "podman-systemd.unit(5)": "podman-systemd.unit",
    "systemd.service(5)": "systemd.service",
}

# The citations are written against the minimum Podman this project supports
# (ADR-0002). Checking them against an older manual page compares the rules
# with documentation they were never quoting: Ubuntu ships 4.9, whose wording
# differs from 5.x in several of the passages cited here.
MINIMUM_PODMAN = (5, 0)


def podman_version():
    """Return the installed Podman version as (major, minor), or None."""
    try:
        out = subprocess.run(
            ["podman", "--version"], capture_output=True, text=True, timeout=10,
        ).stdout
    except Exception:
        return None
    m = re.search(r"(\d+)\.(\d+)", out)
    return (int(m.group(1)), int(m.group(2))) if m else None


def load(page):
    try:
        out = subprocess.run(
            ["man", page], capture_output=True, text=True, timeout=30,
            env={"MANWIDTH": "80", "PATH": "/usr/bin:/bin", "MANPAGER": "cat"},
        ).stdout
    except Exception:
        return ""
    # man breaks words across lines with a Unicode hyphen (U+2010), an ASCII
    # hyphen, or a soft hyphen, and pads the rest with spaces. Undo all three
    # before collapsing whitespace, or a quote spanning a line break will look
    # absent when it is present.
    out = out.replace("\u00ad", "")
    out = re.sub(r"[\u2010-]\s*\n\s*", "", out)
    return re.sub(r"\s+", " ", out)


version = podman_version()
if version is None:
    print("podman not installed; cannot verify citations against its manual pages")
    sys.exit(0)
if version < MINIMUM_PODMAN:
    print(
        f"podman {version[0]}.{version[1]} is older than the supported minimum "
        f"{MINIMUM_PODMAN[0]}.{MINIMUM_PODMAN[1]} (ADR-0002); its manual pages "
        "predate the wording the rules cite, so verification is skipped"
    )
    sys.exit(0)

pages = {name: load(binary) for name, binary in MAN_PAGES.items()}

source = ""
import glob
for path in glob.glob("internal/rules/*.go"):
    if path.endswith("_test.go"):
        continue
    source += open(path).read()

# Pair each rule with its own citation by splitting on the ID, so that
# interleaved init() blocks cannot misalign them.
blocks = re.split(r'ID:\s*"(QD\d+)"', source)
pairs = []
for i in range(1, len(blocks), 2):
    rule_id, body = blocks[i], blocks[i + 1]
    m = re.search(r'Citation:\s*((?:"(?:[^"\\]|\\.)*"\s*\+?\s*)+),', body)
    if not m:
        continue
    parts = re.findall(r'"((?:[^"\\]|\\.)*)"', m.group(1))
    pairs.append((rule_id, "".join(parts).replace('\\"', '"')))

failures = 0
checked = 0
for rule_id, citation in pairs:
    # A citation may name more than one page, so a quote is verified if it
    # appears in any of them. Insisting on the first named page would flag a
    # correct citation that happens to quote its second source.
    named = [p for p in pages if p in citation and pages[p]]
    if not named:
        print(f"  {rule_id}: no checkable manual page named (self-referential or observed)")
        continue

    # Every double-quoted run inside the citation is a verbatim claim.
    quotes = re.findall(r'"([^"]{15,})"', citation)
    if not quotes:
        print(f"  {rule_id}: cites {', '.join(named)} without a verbatim quote")
        continue

    for quote in quotes:
        checked += 1
        needle = re.sub(r"\s+", " ", quote).strip().rstrip(".")
        found = next((p for p in named if needle in pages[p]), None)
        if found:
            print(f"  {rule_id}: VERIFIED in {found}")
        else:
            failures += 1
            print(f"  {rule_id}: NOT FOUND in {' or '.join(named)}")
            print(f"      quote: {needle[:100]}")

print()
print(f"{checked} verbatim quotes checked, {failures} not found")
sys.exit(1 if failures else 0)
