#!/usr/bin/env bash
# Mutation check: flip a load-bearing condition and confirm a test fails.
#
# A test suite that passes against deliberately broken code is decoration. This
# applies one mutation at a time, runs the affected package with the test cache
# disabled, and reports whether the suite noticed.
#
# Every mutation here corresponds to a claim made in a commit message or in
# docs/spec-review.md. A SURVIVED line means the claim is not actually defended
# by a test, and is a gap to close rather than a curiosity.
#
# Note the -count=1: without it Go serves a cached pass and every mutation looks
# survivable. That bug in an earlier version of this script produced six false
# "gaps" before it was spotted.
#
# Usage: bash scripts/mutation-check.sh
set -uo pipefail
cd /home/oliverh/repos/github/MatrixMagician/QuadDoc

run_mutation() {
  local name="$1" file="$2" pkg="$3" script="$4"
  cp "$file" /tmp/mut.bak
  python3 -c "$script" || { cp /tmp/mut.bak "$file"; printf '%-46s SCRIPT-FAILED\n' "$name"; return; }

  # A mutation whose target string has drifted changes nothing and then reports
  # SURVIVED, which looks like a missing test but is a stale script. Refactors
  # cause this routinely, so check the file actually changed.
  if cmp -s /tmp/mut.bak "$file"; then
    printf '%-46s NOT-APPLIED  <-- stale mutation, fix the script\n' "$name"
    cp /tmp/mut.bak "$file"
    return
  fi

  if go test -count=1 "$pkg" >/dev/null 2>&1; then
    printf '%-46s SURVIVED  <-- gap\n' "$name"
  else
    printf '%-46s caught\n' "$name"
  fi
  cp /tmp/mut.bak "$file"
}

P="internal/rules"

run_mutation "QD004 ignores the system-path deny-list" "$P/selinux.go" ./$P "
p='$P/selinux.go'; s=open(p).read()
s=s.replace('\t\t\tsp, unsafe := systemPathFor(m.Source)\n\t\t\tif !unsafe {','\t\t\tsp, unsafe := systemPathFor(m.Source)\n\t\t\tif !unsafe || true {')
open(p,'w').write(s)"

run_mutation "QD004 flags subdirectories too (too broad)" "$P/selinux.go" ./$P "
p='$P/selinux.go'; s=open(p).read()
s=s.replace('\t\tif clean == sp.Path {','\t\tif clean == sp.Path || strings.HasPrefix(clean, sp.Path) {')
open(p,'w').write(s)"

run_mutation "QD001 ignores the SELinux downgrade ladder" "$P/rules.go" ./$P "
p='$P/rules.go'; s=open(p).read()
s=s.replace('\tcase hostctx.SELinuxPermissive:\n\t\treturn Note, true','\tcase hostctx.SELinuxPermissive:\n\t\treturn def, true')
open(p,'w').write(s)"

run_mutation "SELinux disabled no longer suppresses" "$P/rules.go" ./$P "
p='$P/rules.go'; s=open(p).read()
s=s.replace('\tcase hostctx.SELinuxDisabled:\n\t\treturn Note, false','\tcase hostctx.SELinuxDisabled:\n\t\treturn Note, true')
open(p,'w').write(s)"

run_mutation "QD011 accepts a named group" "$P/rootless.go" ./$P "
p='$P/rootless.go'; s=open(p).read()
s=s.replace('\t\t\tif g == \"\" || g == \"keep-groups\" {','\t\t\tif true {')
open(p,'w').write(s)"

run_mutation "QD030 ignores pod membership" "$P/network.go" ./$P "
p='$P/network.go'; s=open(p).read()
s=s.replace('\t\tif u.Pod != \"\" {\n\t\t\tcontinue\n\t\t}','')
open(p,'w').write(s)"

run_mutation "QD031 hardcodes 1024 instead of the sysctl" "$P/network.go" ./$P "
p='$P/network.go'; s=open(p).read()
s=s.replace('\tthreshold, known := c.Host.UnprivilegedPortStart()','\tthreshold, known := 1024, true\n\t_ = c.Host.UnprivilegedPortStart')
open(p,'w').write(s)"

run_mutation "QD032 drops the systemd- prefix note" "$P/network.go" ./$P "
p='$P/network.go'; s=open(p).read()
s=s.replace('would create \`systemd-%s\`, so a rename changes the object name too.\",','would create it, so a rename changes the object name too.\",')
s=s.replace('\t\t\t\tfileName, u.Name),','\t\t\t\tfileName),')
open(p,'w').write(s)"

run_mutation "QD041 reports \${VAR} references as leaks" "$P/hygiene.go" ./$P "
p='$P/hygiene.go'; s=open(p).read()
s=s.replace('\tif strings.HasPrefix(v, \"\$\") || strings.HasPrefix(v, \"%\") {\n\t\treturn false\n\t}','')
open(p,'w').write(s)"

run_mutation "QD040 stops requiring a registry" "$P/hygiene.go" ./$P "
p='$P/hygiene.go'; s=open(p).read()
s=s.replace('\t\t\tcase ref.Registry == \"\":','\t\t\tcase false:')
open(p,'w').write(s)"

run_mutation "QD022 stops exempting pod members" "$P/install.go" ./$P "
p='$P/install.go'; s=open(p).read()
s=s.replace('\t\tif u.Pod != \"\" {\n\t\t\tcontinue\n\t\t}','')
open(p,'w').write(s)"

run_mutation "QD023 accepts unhonoured [Install] keys" "$P/install.go" ./$P "
p='$P/install.go'; s=open(p).read()
s=s.replace('\t\t\tif installKeysHonoured[lower(kv.Key)] {','\t\t\tif true {')
open(p,'w').write(s)"

run_mutation "exit code ignores warnings" "$P/rules.go" ./$P "
p='$P/rules.go'; s=open(p).read()
s=s.replace('\tcase Warning:\n\t\treturn 1','\tcase Warning:\n\t\treturn 0')
open(p,'w').write(s)"

run_mutation "parser joins continuations without a space" "internal/parse/quadlet/parse.go" ./internal/parse/quadlet "
p='internal/parse/quadlet/parse.go'; s=open(p).read()
s=s.replace('strings.Join(kept, \" \")','strings.Join(kept, \"\")')
open(p,'w').write(s)"

run_mutation "parser treats repeated keys as last-wins" "internal/parse/quadlet/parse.go" ./internal/parse/quadlet "
p='internal/parse/quadlet/parse.go'; s=open(p).read()
s=s.replace('\t\t\tout = append(out, e.Value)','\t\t\tout = []string{e.Value}')
open(p,'w').write(s)"

run_mutation "IR counts mounts, not units, as sharing" "internal/ir/ir.go" ./internal/ir "
p='internal/ir/ir.go'; s=open(p).read()
s=s.replace('\t\t\tif m.Type != MountBind || seen[m.Source] {','\t\t\tif m.Type != MountBind {')
open(p,'w').write(s)"

run_mutation "mount options parsed case-insensitively" "internal/ir/ir.go" ./internal/ir "
p='internal/ir/ir.go'; s=open(p).read()
s=s.replace('\t\tif o == opt {','\t\tif strings.EqualFold(o, opt) {')
open(p,'w').write(s)"

run_mutation "hostctx picks the shortest mount prefix" "internal/hostctx/hostctx.go" ./internal/hostctx "
p='internal/hostctx/hostctx.go'; s=open(p).read()
s=s.replace('if !found || len(m.MountPoint) > len(best.MountPoint) {','if !found || len(m.MountPoint) < len(best.MountPoint) {')
open(p,'w').write(s)"

run_mutation "capture copies unit file contents" "internal/hostctx/live.go" ./internal/hostctx "
p='internal/hostctx/live.go'; s=open(p).read()
s=s.replace('os.WriteFile(filepath.Join(unitDir, name), nil, 0o644)','os.WriteFile(filepath.Join(unitDir, name), []byte(\"[Container]\\nEnvironment=SECRET=hunter2\\n\"), 0o644)')
open(p,'w').write(s)"

run_mutation "suppressions no longer require a reason" "internal/config/config.go" ./internal/config "
p='internal/config/config.go'; s=open(p).read()
s=s.replace('\t\t\tif s.Reason != \"\" && s.Covers(f.RuleID) {','\t\t\tif s.Covers(f.RuleID) {')
open(p,'w').write(s)"

run_mutation "config accepts unknown rule IDs" "internal/config/config.go" ./internal/config "
p='internal/config/config.go'; s=open(p).read()
s=s.replace('\t\tif _, known := rules.Lookup(key); !known {','\t\tif _, known := rules.Lookup(key); false {')
open(p,'w').write(s)"

run_mutation "generator guesses an SELinux label" "internal/generate/generate.go" ./internal/generate "
p='internal/generate/generate.go'; s=open(p).read()
s=s.replace('\t\t// Deliberately not guessing at a label here','\t\toptions = append(options, \"Z\")\n\t\t// Deliberately not guessing at a label here')
open(p,'w').write(s)"

run_mutation "generator drops the shared network" "internal/generate/generate.go" ./internal/generate "
p='internal/generate/generate.go'; s=open(p).read()
s=s.replace('\t\tu.key(\"Network\", networkUnit+\".network\")','')
open(p,'w').write(s)"

run_mutation "unless-stopped passed through verbatim" "internal/generate/generate.go" ./internal/generate "
p='internal/generate/generate.go'; s=open(p).read()
s=s.replace('\t\treturn \"always\", \"compose used \`restart: unless-stopped\`','\t\treturn \"unless-stopped\", \"compose used \`restart: unless-stopped\`')
open(p,'w').write(s)"

run_mutation "SARIF ruleIndex is always zero" "internal/output/sarif.go" ./internal/output "
p='internal/output/sarif.go'; s=open(p).read()
s=s.replace('\t\t\tRuleIndex: i,','\t\t\tRuleIndex: 0,')
open(p,'w').write(s)"

run_mutation "JSON emits null instead of []" "internal/output/json.go" ./internal/output "
p='internal/output/json.go'; s=open(p).read()
s=s.replace('\tif findings == nil {\n\t\tfindings = []rules.Finding{}\n\t}','')
open(p,'w').write(s)"

M="cmd/quaddoc/main.go"

run_mutation "flag parser ignores flags after the path" "$M" ./cmd/quaddoc "
p='$M'; s=open(p).read()
s=s.replace('\tpositional, err := parseArgs(fs, args)\n\tif err != nil {\n\t\treturn 2\n\t}\n\n\tpath := \"\"','\tif err := fs.Parse(args); err != nil {\n\t\treturn 2\n\t}\n\tpositional := fs.Args()\n\t_ = positional\n\tpath := \"\"')
s=s.replace('\tpath := \"\"\n\tif len(positional) > 0 {\n\t\tpath = positional[0]\n\t}','\tpath := fs.Arg(0)')
open(p,'w').write(s)"

run_mutation "fix writes without --write" "$M" ./cmd/quaddoc "
p='$M'; s=open(p).read()
s=s.replace('\tif !*write {','\tif false {')
open(p,'w').write(s)"

run_mutation "convert --dry-run also writes to disk" "$M" ./cmd/quaddoc "
p='$M'; s=open(p).read()
s=s.replace('\tif *dryRun {','\tif *dryRun && false {')
open(p,'w').write(s)"

run_mutation "--host-context accepts a missing directory" "$M" ./cmd/quaddoc "
p='$M'; s=open(p).read()
s=s.replace('\t\tinfo, err := os.Stat(flag)\n\t\tif err != nil {','\t\tinfo, err := os.Stat(flag)\n\t\tif false {')
s=s.replace('\t\tif !info.IsDir() {','\t\tif info != nil \u0026\u0026 !info.IsDir() \u0026\u0026 false {')
open(p,'w').write(s)"

run_mutation "config errors are swallowed" "$M" ./cmd/quaddoc "
p='$M'; s=open(p).read()
s=s.replace('\tprojectConfig, err := config.Load(paths[0])\n\tif err != nil {','\tprojectConfig, err := config.Load(paths[0])\n\tif false {')
s=s.replace('\truleConfig := projectConfig.RuleConfig()','\t_ = err\n\tif projectConfig == nil {\n\t\tprojectConfig = \u0026config.Config{Disabled: map[string]bool{}, Severity: map[string]rules.Severity{}}\n\t}\n\truleConfig := projectConfig.RuleConfig()')
open(p,'w').write(s)"

run_mutation "suppressions are never applied" "$M" ./cmd/quaddoc "
p='$M'; s=open(p).read()
s=s.replace('projectConfig.ApplySuppressions(engine.Run(project), suppressions(project))','engine.Run(project)')
open(p,'w').write(s)"

run_mutation "--sarif falls back to human output" "$M" ./cmd/quaddoc "
p='$M'; s=open(p).read()
s=s.replace('\tcase *asSARIF:','\tcase false:')
open(p,'w').write(s)"

run_mutation "--rule filter is ignored by fix" "$M" ./cmd/quaddoc "
p='$M'; s=open(p).read()
s=s.replace('\t\tif id = strings.ToUpper(strings.TrimSpace(id)); id != \"\" {\n\t\t\topts.Only[id] = true\n\t\t}','\t\t_ = id')
open(p,'w').write(s)"

run_mutation "doctor reports nothing about the host" "$M" ./cmd/quaddoc "
p='$M'; s=open(p).read()
s=s.replace('\tfor _, line := range hostctx.Describe(host) {\n\t\tfmt.Println(line)\n\t}','\t_ = host')
open(p,'w').write(s)"

run_mutation "capture writes to the wrong place" "$M" ./cmd/quaddoc "
p='$M'; s=open(p).read()
s=s.replace('\tif err := hostctx.Capture(*out); err != nil {','\tif err := hostctx.Capture(*out + \"-elsewhere\"); err != nil {')
open(p,'w').write(s)"

run_mutation "rules --markdown prints the plain listing" "$M" ./cmd/quaddoc "
p='$M'; s=open(p).read()
s=s.replace('\tif *asMarkdown {','\tif false {')
open(p,'w').write(s)"

# Newly covered ir package.
run_mutation "LoadProject ignores non-unit extensions check" "internal/ir/load.go" ./internal/ir "
p='internal/ir/load.go'; s=open(p).read()
s=s.replace('\t\t\tif KindFromPath(p) != KindUnknown {\n\t\t\t\tpaths = append(paths, p)\n\t\t\t}','\t\t\tpaths = append(paths, p)')
open(p,'w').write(s)"

run_mutation "loader stops recording key lines" "internal/ir/load.go" ./internal/ir "
p='internal/ir/load.go'; s=open(p).read()
s=s.replace('\t\tu.SetKeyLine(e.Key, e.Line)','')
open(p,'w').write(s)"

run_mutation "HealthCmd=none counts as a healthcheck" "internal/ir/load.go" ./internal/ir "
p='internal/ir/load.go'; s=open(p).read()
s=s.replace('u.HasHealthCmd = e.Value != \"\" \u0026\u0026 e.Value != \"none\"','u.HasHealthCmd = e.Value != \"\"')
open(p,'w').write(s)"

run_mutation "Restart read from the wrong section" "internal/ir/load.go" ./internal/ir "
p='internal/ir/load.go'; s=open(p).read()
s=s.replace('f.Lookup(\"Service\", \"Restart\")','f.Lookup(\"Container\", \"Restart\")')
open(p,'w').write(s)"

run_mutation "NamedVolumeUsers counts mounts not units" "internal/ir/ir.go" ./internal/ir "
p='internal/ir/ir.go'; s=open(p).read()
s=s.replace('\t\t\tif m.Type != MountNamed || seen[m.Source] {','\t\t\tif m.Type != MountNamed {')
open(p,'w').write(s)"

run_mutation "UnitByName ignores the unit kind" "internal/ir/ir.go" ./internal/ir "
p='internal/ir/ir.go'; s=open(p).read()
s=s.replace('\t\tif u.Name == name \u0026\u0026 u.Kind == kind {','\t\tif u.Name == name {')
open(p,'w').write(s)"


echo
echo "Restoring and confirming the tree is clean:"
go test ./... 2>&1 | grep -cE '^ok' | xargs -I{} echo "  {} packages passing"
