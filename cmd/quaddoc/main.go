// Command quaddoc converts docker-compose projects into Podman Quadlet units
// and audits the result.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/MatrixMagician/quaddoc/internal/hostctx"
	"github.com/MatrixMagician/quaddoc/internal/ir"
	"github.com/MatrixMagician/quaddoc/internal/output"
	"github.com/MatrixMagician/quaddoc/internal/rules"
)

// version is stamped at build time with -ldflags.
var version = "dev"

const usage = `quaddoc - convert, lint, and diagnose Podman Quadlets

Usage:
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
	if err := fs.Parse(args); err != nil {
		return 2
	}

	paths := fs.Args()
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
