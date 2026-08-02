// Command quaddoc converts docker-compose projects into Podman Quadlet units
// and audits the result.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

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
  quaddoc convert <compose.yaml>   generate Quadlet units from a compose file
  quaddoc lint <path...>       audit Quadlet units
  quaddoc rules [QD###]        show the rule reference
  quaddoc version              print the version

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
	verbose := fs.Bool("explain", false, "include each rule's rationale and citation")
	disable := fs.String("disable", "", "comma-separated rule IDs to skip")

	paths, err := parseArgs(fs, args)
	if err != nil {
		return 2
	}
	if len(paths) == 0 {
		fmt.Fprintln(os.Stderr, "quaddoc lint: no paths given")
		return 2
	}

	config := rules.Config{Disabled: map[string]bool{}}
	for _, id := range strings.Split(*disable, ",") {
		if id = strings.ToUpper(strings.TrimSpace(id)); id != "" {
			config.Disabled[id] = true
		}
	}

	// Load every path into one project. Rules reason across the whole set, so
	// linting two directories together is meaningfully different from linting
	// each alone, and the user chose to name them together.
	project := &ir.Project{}
	for _, path := range paths {
		p, err := ir.LoadProject(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "quaddoc: %v\n", err)
			return 2
		}
		if project.Root == "" {
			project.Root = p.Root
		}
		project.Units = append(project.Units, p.Units...)
	}
	project.Sort()

	if len(project.Units) == 0 {
		fmt.Fprintf(os.Stderr, "quaddoc: no Quadlet units found in %s\n", strings.Join(paths, ", "))
		return 2
	}

	engine := &rules.Engine{Config: config, Host: hostctx.Unknown{}}
	findings := engine.Run(project)

	if *asJSON {
		if err := output.JSON(os.Stdout, findings); err != nil {
			fmt.Fprintf(os.Stderr, "quaddoc: writing JSON: %v\n", err)
			return 2
		}
	} else {
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
	if err := fs.Parse(args); err != nil {
		return 2
	}

	if id := fs.Arg(0); id != "" {
		r, ok := rules.Lookup(id)
		if !ok {
			fmt.Fprintf(os.Stderr, "quaddoc: no such rule %q\n", id)
			return 2
		}
		fmt.Printf("%s  %s\n\n", r.ID, r.Summary)
		fmt.Printf("Severity: %s\n", r.DefaultSeverity)
		fmt.Printf("Fixable:  %t\n\n", r.Fixable)
		fmt.Printf("%s\n\n", r.Rationale)
		fmt.Printf("Source: %s\n", r.Citation)
		return 0
	}

	for _, r := range rules.All() {
		fmt.Printf("%s  %-8s %s\n", r.ID, r.DefaultSeverity, r.Summary)
	}
	return 0
}
