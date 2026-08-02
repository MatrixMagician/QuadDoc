// Command quaddoc converts docker-compose projects into Podman Quadlet units
// and audits the result.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/MatrixMagician/quaddoc/internal/config"
	"github.com/MatrixMagician/quaddoc/internal/fix"
	"github.com/MatrixMagician/quaddoc/internal/generate"
	"github.com/MatrixMagician/quaddoc/internal/hostctx"
	"github.com/MatrixMagician/quaddoc/internal/ir"
	"github.com/MatrixMagician/quaddoc/internal/output"
	"github.com/MatrixMagician/quaddoc/internal/parse/compose"
	"github.com/MatrixMagician/quaddoc/internal/rules"
)

// version is stamped at build time with -ldflags.
var version = "dev"

const usage = `quaddoc - convert, lint, and diagnose Podman Quadlets

Usage:
  quaddoc convert <compose.yaml>      generate Quadlet units from a compose file
  quaddoc lint <path...>              audit Quadlet units
  quaddoc fix <path...>               apply safe remediations (diff preview by default)
  quaddoc capture-context [--out dir] record this system's context for replay
  quaddoc doctor                      report what quaddoc detects on this system
  quaddoc rules [QD###]               show the rule reference
  quaddoc version                     print the version

Run 'quaddoc <command> -h' for the options of a command.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}

	switch os.Args[1] {
	case "convert":
		os.Exit(runConvert(os.Args[2:]))
	case "lint":
		os.Exit(runLint(os.Args[2:]))
	case "fix":
		os.Exit(runFix(os.Args[2:]))
	case "capture-context":
		os.Exit(runCapture(os.Args[2:]))
	case "doctor":
		os.Exit(runDoctor(os.Args[2:]))
	case "rules":
		os.Exit(runRules(os.Args[2:]))
	case "version", "--version", "-v":
		fmt.Println("quaddoc", version)
		os.Exit(0)
	case "help", "--help", "-h":
		fmt.Print(usage)
		os.Exit(0)
	default:
		fmt.Fprintf(os.Stderr, "quaddoc: unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}
}

func runLint(args []string) int {
	fs := flag.NewFlagSet("lint", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "emit findings as JSON")
	asSARIF := fs.Bool("sarif", false, "emit findings as SARIF 2.1.0, for CI and code review")
	verbose := fs.Bool("explain", false, "include each rule's rationale and citation")
	disable := fs.String("disable", "", "comma-separated rule IDs to skip")
	hostContext := fs.String("host-context", "",
		`consult the host: "live" for this system, or a directory captured by capture-context`)

	paths, err := parseArgs(fs, args)
	if err != nil {
		return 2
	}
	if len(paths) == 0 {
		fmt.Fprintln(os.Stderr, "quaddoc lint: no paths given")
		return 2
	}

	projectConfig, err := config.Load(paths[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "quaddoc: %v\n", err)
		return 2
	}
	ruleConfig := projectConfig.RuleConfig()
	for _, id := range strings.Split(*disable, ",") {
		if id = strings.ToUpper(strings.TrimSpace(id)); id != "" {
			ruleConfig.Disabled[id] = true
		}
	}

	project, err := loadProject(paths)
	if err != nil {
		fmt.Fprintf(os.Stderr, "quaddoc: %v\n", err)
		return 2
	}

	host, err := resolveHostContext(*hostContext)
	if err != nil {
		fmt.Fprintf(os.Stderr, "quaddoc: %v\n", err)
		return 2
	}

	engine := &rules.Engine{Config: ruleConfig, Host: host}
	findings := config.ApplySuppressions(engine.Run(project), suppressions(project))

	switch {
	case *asSARIF:
		if err := output.SARIF(os.Stdout, findings, version); err != nil {
			fmt.Fprintf(os.Stderr, "quaddoc: writing SARIF: %v\n", err)
			return 2
		}
	case *asJSON:
		if err := output.JSON(os.Stdout, findings); err != nil {
			fmt.Fprintf(os.Stderr, "quaddoc: writing JSON: %v\n", err)
			return 2
		}
	default:
		output.Human{
			Colour:  output.ColourEnabled(os.Stdout),
			Verbose: *verbose,
		}.Render(os.Stdout, findings)
	}

	return rules.ExitCode(findings)
}

// parseArgs separates flags from positional arguments before parsing, so that
// `quaddoc convert file.yaml --out dir` works as well as `--out dir file.yaml`.
// Go's flag package stops at the first non-flag argument, which surprises
// everyone who has used any other command-line tool.
func parseArgs(fs *flag.FlagSet, args []string) ([]string, error) {
	var flags, positional []string

	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			positional = append(positional, args[i+1:]...)
			i = len(args)
		case strings.HasPrefix(a, "-"):
			flags = append(flags, a)
			// A flag that takes a value and was not written as --flag=value
			// consumes the next argument.
			name := strings.TrimLeft(strings.SplitN(a, "=", 2)[0], "-")
			if !strings.Contains(a, "=") && takesValue(fs, name) && i+1 < len(args) {
				i++
				flags = append(flags, args[i])
			}
		default:
			positional = append(positional, a)
		}
	}

	if err := fs.Parse(flags); err != nil {
		return nil, err
	}
	return positional, nil
}

// takesValue reports whether a flag needs a following argument. Boolean flags
// do not, which is why they can be written bare.
func takesValue(fs *flag.FlagSet, name string) bool {
	f := fs.Lookup(name)
	if f == nil {
		return false
	}
	bf, ok := f.Value.(interface{ IsBoolFlag() bool })
	return !(ok && bf.IsBoolFlag())
}

func runConvert(args []string) int {
	fs := flag.NewFlagSet("convert", flag.ExitOnError)
	out := fs.String("out", "units", "directory to write units into")
	pod := fs.Bool("pod", false, "emit a single .pod unit instead of a shared .network")
	noAnnotate := fs.Bool("no-annotate", false, "omit explanatory comments from the units")
	dryRun := fs.Bool("dry-run", false, "print the units instead of writing them")

	positional, err := parseArgs(fs, args)
	if err != nil {
		return 2
	}

	path := ""
	if len(positional) > 0 {
		path = positional[0]
	}
	if path == "" {
		fmt.Fprintln(os.Stderr, "quaddoc convert: no compose file given")
		return 2
	}

	project, err := compose.Load(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "quaddoc: %v\n", err)
		return 2
	}

	result := generate.Convert(project, generate.Options{
		Pod:      *pod,
		Annotate: !*noAnnotate,
	})

	if *dryRun {
		for i, u := range result.Units {
			if i > 0 {
				fmt.Println()
			}
			fmt.Printf("# ---- %s ----\n%s", u.Name, u.Content)
		}
	} else {
		if err := os.MkdirAll(*out, 0o755); err != nil {
			fmt.Fprintf(os.Stderr, "quaddoc: creating %s: %v\n", *out, err)
			return 2
		}
		for _, u := range result.Units {
			dest := filepath.Join(*out, u.Name)
			if err := os.WriteFile(dest, []byte(u.Content), 0o644); err != nil {
				fmt.Fprintf(os.Stderr, "quaddoc: writing %s: %v\n", dest, err)
				return 2
			}
		}
		fmt.Fprintf(os.Stderr, "Wrote %d units to %s\n", len(result.Units), *out)
	}

	// Translation notes go to stderr so that --dry-run output stays pipeable.
	worst := 0
	for _, n := range result.Notes {
		fmt.Fprintf(os.Stderr, "%s: %s\n", n.Severity, n.Message)
		if n.Severity == "warning" && worst < 1 {
			worst = 1
		}
		if n.Severity == "error" {
			worst = 2
		}
	}
	if len(result.Notes) > 0 {
		fmt.Fprintf(os.Stderr, "\nRun `quaddoc lint %s` to audit the result.\n", *out)
	}
	return worst
}

func runRules(args []string) int {
	fs := flag.NewFlagSet("rules", flag.ExitOnError)
	asMarkdown := fs.Bool("markdown", false, "render the reference as Markdown, for publishing")

	positional, err := parseArgs(fs, args)
	if err != nil {
		return 2
	}

	if *asMarkdown {
		fmt.Print(output.RulesMarkdown())
		return 0
	}

	id := ""
	if len(positional) > 0 {
		id = positional[0]
	}
	if id != "" {
		r, ok := rules.Lookup(id)
		if !ok {
			fmt.Fprintf(os.Stderr, "quaddoc: no such rule %q\n", id)
			return 2
		}
		fmt.Printf("%s  %s\n\n", r.ID, r.Summary)
		fmt.Printf("Severity:     %s\n", r.DefaultSeverity)
		fmt.Printf("Fixable:      %t\n", r.Fixable)
		fmt.Printf("Host context: %t\n\n", r.NeedsHostContext)
		fmt.Printf("%s\n\n", r.Rationale)
		fmt.Printf("Source: %s\n", r.Citation)
		return 0
	}

	for _, r := range rules.All() {
		fmt.Printf("%s  %-8s %s\n", r.ID, r.DefaultSeverity, r.Summary)
	}
	return 0
}

// resolveHostContext turns the --host-context flag into a context.
//
// The default is to know nothing, so that findings are hedged unless the user
// asked quaddoc to look at their system. Reading the host should be a choice,
// not something that happens because a rule felt like it.
func resolveHostContext(flag string) (hostctx.Context, error) {
	switch flag {
	case "":
		return hostctx.Unknown{}, nil
	case "live":
		return hostctx.NewLive(), nil
	default:
		info, err := os.Stat(flag)
		if err != nil {
			return nil, fmt.Errorf("reading captured context %s: %w", flag, err)
		}
		if !info.IsDir() {
			return nil, fmt.Errorf("captured context %s is not a directory", flag)
		}
		return hostctx.NewReplay(flag), nil
	}
}

func runCapture(args []string) int {
	fs := flag.NewFlagSet("capture-context", flag.ExitOnError)
	out := fs.String("out", "quaddoc-context", "directory to write the context into")

	if _, err := parseArgs(fs, args); err != nil {
		return 2
	}

	if err := hostctx.Capture(*out); err != nil {
		fmt.Fprintf(os.Stderr, "quaddoc: %v\n", err)
		return 2
	}

	fmt.Fprintf(os.Stderr, "Captured this system's context to %s\n\n", *out)
	fmt.Fprintf(os.Stderr, "Lint against it from anywhere with:\n\n    quaddoc lint --host-context=%s <units>\n", *out)
	return 0
}

func runDoctor(args []string) int {
	fs := flag.NewFlagSet("doctor", flag.ExitOnError)
	hostContext := fs.String("host-context", "live", `"live" or a captured directory`)

	if _, err := parseArgs(fs, args); err != nil {
		return 2
	}

	host, err := resolveHostContext(*hostContext)
	if err != nil {
		fmt.Fprintf(os.Stderr, "quaddoc: %v\n", err)
		return 2
	}

	fmt.Println("quaddoc", version)
	fmt.Println()
	for _, line := range hostctx.Describe(host) {
		fmt.Println(line)
	}

	fmt.Println()
	if path := findQuadletGenerator(); path != "" {
		fmt.Println("Quadlet generator:", path)
	} else {
		fmt.Println("Quadlet generator: not found (conversion still works; " +
			"only the generator cross-check is unavailable)")
	}

	fmt.Println()
	fmt.Printf("Rules registered: %d\n", len(rules.All()))
	return 0
}

// findQuadletGenerator locates the Quadlet generator, which is not on PATH.
// Its absence is reported rather than treated as an error: quaddoc does not
// depend on podman being installed.
func findQuadletGenerator() string {
	for _, path := range []string{
		"/usr/libexec/podman/quadlet",
		"/usr/lib/podman/quadlet",
		"/usr/local/libexec/podman/quadlet",
	} {
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			return path
		}
	}
	return ""
}

func runFix(args []string) int {
	fs := flag.NewFlagSet("fix", flag.ExitOnError)
	write := fs.Bool("write", false, "apply the changes instead of previewing them")
	only := fs.String("rule", "", "comma-separated rule IDs to fix; default is every fixable rule")
	hostContext := fs.String("host-context", "",
		`consult the host: "live" for this system, or a directory captured by capture-context`)

	paths, err := parseArgs(fs, args)
	if err != nil {
		return 2
	}
	if len(paths) == 0 {
		fmt.Fprintln(os.Stderr, "quaddoc fix: no paths given")
		return 2
	}

	project, err := loadProject(paths)
	if err != nil {
		fmt.Fprintf(os.Stderr, "quaddoc: %v\n", err)
		return 2
	}

	host, err := resolveHostContext(*hostContext)
	if err != nil {
		fmt.Fprintf(os.Stderr, "quaddoc: %v\n", err)
		return 2
	}

	engine := &rules.Engine{Host: host}
	findings := engine.Run(project)

	opts := fix.Options{Only: map[string]bool{}}
	for _, id := range strings.Split(*only, ",") {
		if id = strings.ToUpper(strings.TrimSpace(id)); id != "" {
			opts.Only[id] = true
		}
	}

	result, err := fix.Apply(project, findings, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "quaddoc: %v\n", err)
		return 2
	}

	if len(result.Changes) == 0 {
		fmt.Println("Nothing to fix.")
		reportUnfixed(result.Unfixed)
		return 0
	}

	if !*write {
		for _, change := range result.Changes {
			fmt.Print(fix.Diff(change))
			fmt.Println()
		}
		fmt.Fprintf(os.Stderr, "%d file(s) would change. Re-run with --write to apply.\n",
			len(result.Changes))
		reportUnfixed(result.Unfixed)
		return 0
	}

	if err := fix.Write(result); err != nil {
		fmt.Fprintf(os.Stderr, "quaddoc: %v\n", err)
		return 2
	}
	for _, change := range result.Changes {
		verb := "updated"
		if change.Created {
			verb = "created"
		}
		fmt.Printf("%s %s (%s)\n", verb, change.Path, strings.Join(change.Rules, ", "))
	}
	reportUnfixed(result.Unfixed)
	return 0
}

// reportUnfixed tells the user what is left, so a clean fix run is not mistaken
// for a clean lint.
func reportUnfixed(unfixed []rules.Finding) {
	if len(unfixed) == 0 {
		return
	}

	byRule := map[string]int{}
	for _, f := range unfixed {
		byRule[f.RuleID]++
	}
	ids := make([]string, 0, len(byRule))
	for id := range byRule {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	fmt.Fprintf(os.Stderr, "\n%d finding(s) have no mechanical fix and need a decision from you:\n",
		len(unfixed))
	for _, id := range ids {
		summary := id
		if r, ok := rules.Lookup(id); ok {
			summary = id + " " + r.Summary
		}
		fmt.Fprintf(os.Stderr, "  %s (%d)\n", summary, byRule[id])
	}
	fmt.Fprintln(os.Stderr, "\nRun `quaddoc lint` to see them in full.")
}

// loadProject reads every named path into one project. Rules reason across the
// whole set, so paths named together are linted together.
func loadProject(paths []string) (*ir.Project, error) {
	project := &ir.Project{}
	for _, path := range paths {
		p, err := ir.LoadProject(path)
		if err != nil {
			return nil, err
		}
		if project.Root == "" {
			project.Root = p.Root
		}
		project.Units = append(project.Units, p.Units...)
	}
	project.Sort()

	if len(project.Units) == 0 {
		return nil, fmt.Errorf("no Quadlet units found in %s", strings.Join(paths, ", "))
	}
	return project, nil
}

// suppressions gathers inline directives from every unit in a project.
func suppressions(project *ir.Project) map[string][]config.Suppression {
	out := map[string][]config.Suppression{}
	for _, u := range project.Units {
		if u.Source == nil {
			continue
		}
		if found := config.ParseSuppressions(u.Path, u.Source.Render()); len(found) > 0 {
			out[u.Path] = found
		}
	}
	return out
}
