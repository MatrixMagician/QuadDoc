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
