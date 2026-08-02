// Package rules holds the rule engine and the rule catalogue.
//
// A rule is a single-file affair: the struct, its registration, its
// documentation, and its tests all live together, and the same metadata that
// drives the engine renders the `quaddoc rules` reference page. There is no
// separate docs step to forget.
//
// Rules are given a Project, never a lone unit. Several checks are only
// answerable across the whole set: whether a bind source is shared between
// units (QD001 and QD002), whether siblings can resolve each other (QD030),
// whether a name collides (QD032). See docs/spec-review.md finding F3.
package rules

import (
	"fmt"
	"sort"
	"strings"

	"github.com/MatrixMagician/quaddoc/internal/hostctx"
	"github.com/MatrixMagician/quaddoc/internal/ir"
)

// Severity is how seriously a finding should be taken. It drives the exit code.
type Severity int

const (
	// Note is informational: worth knowing, not worth blocking on.
	Note Severity = iota
	// Warning is a probable problem, or a certain one with a mild effect.
	Warning
	// Error is a problem that will stop the unit working as intended.
	Error
)

func (s Severity) String() string {
	switch s {
	case Error:
		return "error"
	case Warning:
		return "warning"
	}
	return "note"
}

// ParseSeverity converts the textual form used in configuration files.
func ParseSeverity(s string) (Severity, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "error":
		return Error, true
	case "warning", "warn":
		return Warning, true
	case "note", "info":
		return Note, true
	}
	return Note, false
}

// Confidence records whether a finding was reasoned from the units alone or
// confirmed against the host. The same rule can produce either, and the wording
// differs: without host context we say a thing may be true, with it we say it
// is.
type Confidence string

const (
	// Possible means the finding was derived from the units alone.
	Possible Confidence = "possible"
	// Confirmed means host context established the fact.
	Confirmed Confidence = "confirmed"
)

// Finding is one reported problem.
type Finding struct {
	RuleID     string     `json:"rule"`
	Severity   Severity   `json:"-"`
	SeverityJS string     `json:"severity"`
	Confidence Confidence `json:"confidence"`
	// Unit is the path of the unit the finding concerns.
	Unit string `json:"unit"`
	// Line is where in that unit, or 0 when the finding is about the unit
	// as a whole rather than a particular line.
	Line int `json:"line,omitempty"`
	// Message states what is wrong, in one sentence.
	Message string `json:"message"`
	// Remediation is copy-pasteable, or an explicit statement that no
	// mechanical fix exists and what decision the user must make instead.
	Remediation string `json:"remediation"`

	// Fix carries the structured detail the fix engine needs, so that it
	// applies exactly what the rule decided rather than re-deriving it from
	// the prose. Empty for findings with no mechanical fix.
	Fix map[string]string `json:"-"`

	// hostDowngraded records that host context lowered this finding's
	// severity, as opposed to the rule simply grading its own output. The
	// distinction matters when configuration also has an opinion: a project
	// may raise a rule it cares about, but it cannot raise a finding the host
	// has established does not apply here. See ADR-0004.
	hostDowngraded bool
}

// MarkHostDowngraded records that host context lowered this finding's
// severity, so configuration does not raise it back. Used by the SELinux
// rules, whose severity depends on whether the kernel enforces policy.
func (f Finding) MarkHostDowngraded() Finding {
	f.hostDowngraded = true
	return f
}

// Rule is one check over a project.
//
// Metadata lives beside the implementation so the reference documentation
// cannot drift from what the code does.
type Rule struct {
	// ID is the QD### identifier.
	ID string
	// Summary is a one-line description, shown in listings.
	Summary string
	// Rationale explains why this matters, in prose, for the reference page.
	Rationale string
	// Citation names the documentation or observed behaviour the rule
	// encodes. A rule without one does not ship: see CLAUDE.md.
	Citation string
	// DefaultSeverity applies unless configuration overrides it.
	DefaultSeverity Severity
	// NeedsHostContext marks rules whose findings are only confirmed with a
	// host context, and which must degrade gracefully without one.
	NeedsHostContext bool
	// Fixable marks rules whose remediation is mechanically applicable and
	// provably semantics-preserving.
	Fixable bool
	// Check runs the rule.
	Check func(*Context) []Finding
}

// Context is what a rule is given: the whole project, the host context if one
// was gathered, and the analysis shared between rules.
type Context struct {
	Project *ir.Project
	// Host is never nil. When no context was gathered it is an
	// unknown-everything implementation, so rules need no nil checks.
	Host hostctx.Context
	// BindSourceUsage counts how many units mount each bind source. Computed
	// once and shared, which is what keeps QD001 and QD002 from
	// contradicting each other.
	BindSourceUsage map[string]int

	// severity resolves a rule's effective severity, honouring configuration.
	severity func(ruleID string, def Severity) Severity
}

// Severity returns the effective severity for a rule, after configuration
// overrides and host-context downgrades.
func (c *Context) Severity(ruleID string, def Severity) Severity {
	if c.severity == nil {
		return def
	}
	return c.severity(ruleID, def)
}

// registry holds every registered rule, keyed by ID.
var registry = map[string]*Rule{}

// Register adds a rule to the catalogue. It panics on a duplicate or malformed
// ID, because both are programming errors that should never reach a release.
func Register(r *Rule) {
	if r.ID == "" {
		panic("rules: rule registered without an ID")
	}
	if r.Citation == "" {
		panic(fmt.Sprintf("rules: %s registered without a citation", r.ID))
	}
	if r.Check == nil {
		panic(fmt.Sprintf("rules: %s registered without a check", r.ID))
	}
	if _, dup := registry[r.ID]; dup {
		panic(fmt.Sprintf("rules: %s registered twice", r.ID))
	}
	registry[r.ID] = r
}

// All returns every registered rule, ordered by ID.
func All() []*Rule {
	out := make([]*Rule, 0, len(registry))
	for _, r := range registry {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Lookup finds a rule by ID.
func Lookup(id string) (*Rule, bool) {
	r, ok := registry[strings.ToUpper(strings.TrimSpace(id))]
	return r, ok
}

// Config controls which rules run and at what severity.
type Config struct {
	// Disabled lists rule IDs to skip entirely.
	Disabled map[string]bool
	// SeverityOverride maps a rule ID to the severity to report it at.
	SeverityOverride map[string]Severity
}

// Engine runs the catalogue over a project.
type Engine struct {
	Config Config
	Host   hostctx.Context
}

// Run executes every enabled rule and returns the findings, ordered
// deterministically so output does not depend on map iteration.
func (e *Engine) Run(p *ir.Project) []Finding {
	host := e.Host
	if host == nil {
		host = hostctx.Unknown{}
	}

	ctx := &Context{
		Project:         p,
		Host:            host,
		BindSourceUsage: p.BindSourceUsage(),
		severity:        e.resolveSeverity(host),
	}

	var findings []Finding
	for _, r := range All() {
		if e.Config.Disabled[r.ID] {
			continue
		}
		for _, f := range r.Check(ctx) {
			// The engine knows which rule it called, so it stamps the ID
			// rather than each finding restating it. A rule that emits a
			// different rule's ID is a bug, not a feature: it would report
			// under an ID whose severity, documentation, and fixability
			// describe something else.
			if f.RuleID != "" && f.RuleID != r.ID {
				panic(fmt.Sprintf("rules: %s emitted a finding for %s", r.ID, f.RuleID))
			}
			f.RuleID = r.ID

			// Apply configuration here rather than trusting each rule to
			// remember. A rule that built its Finding with a literal severity
			// used to ignore .quaddoc.toml silently, which let a project raise
			// a rule to `error` and still pass CI. Two rules had exactly that
			// bug. Doing it centrally makes the mistake impossible rather than
			// merely discouraged.
			//
			// A rule may still lower its own severity below its default, which
			// is how the SELinux downgrade ladder works: a permissive host
			// makes an error a note. That is a fact about the host rather than
			// a preference, so it survives an override that would raise it.
			f.Severity = e.effectiveSeverity(f, f.Severity)
			findings = append(findings, f)
		}
	}

	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].Unit != findings[j].Unit {
			return findings[i].Unit < findings[j].Unit
		}
		if findings[i].Line != findings[j].Line {
			return findings[i].Line < findings[j].Line
		}
		return findings[i].RuleID < findings[j].RuleID
	})

	for i := range findings {
		findings[i].SeverityJS = findings[i].Severity.String()
	}
	return findings
}

// resolveSeverity builds the function a rule sees through Context.Severity.
//
// Rules no longer need to call it: Engine.Run applies the same configuration to
// whatever they return. It remains so that a rule can ask what severity it is
// about to be reported at, which QD022 uses to decide its wording.
func (e *Engine) resolveSeverity(host hostctx.Context) func(string, Severity) Severity {
	return func(ruleID string, def Severity) Severity {
		if s, ok := e.Config.SeverityOverride[ruleID]; ok {
			return s
		}
		return def
	}
}

// effectiveSeverity decides what severity a finding is reported at.
//
// Configuration wins, with one exception: a finding the host context has
// downgraded is not raised back up, because the host established that the
// problem does not apply here and that is an observation rather than a
// preference. See ADR-0004.
func (e *Engine) effectiveSeverity(f Finding, reported Severity) Severity {
	override, configured := e.Config.SeverityOverride[f.RuleID]
	if !configured {
		return reported
	}
	if f.hostDowngraded && override > reported {
		// The host established that this matters less here, which a project
		// preference should not override upwards. Lowering it further is
		// still allowed.
		return reported
	}
	return override
}

// DowngradeForSELinux applies the ladder from ADR-0004 to a severity that
// depends on SELinux being enforced.
//
// Under a permissive kernel the label is still wrong, it simply is not being
// enforced today, and turning enforcing back on would break the container. So
// the finding drops to a note rather than disappearing. When SELinux is absent
// from the kernel the finding is meaningless and is suppressed entirely; the
// caller drops findings for which this returns false.
func DowngradeForSELinux(mode hostctx.SELinuxMode, def Severity) (Severity, bool) {
	switch mode {
	case hostctx.SELinuxEnforcing:
		return def, true
	case hostctx.SELinuxPermissive:
		return Note, true
	case hostctx.SELinuxDisabled:
		return Note, false
	default:
		// No host context: report at the rule's default severity, worded as
		// a possibility rather than a confirmation.
		return def, true
	}
}

// Worst returns the highest severity among findings, and whether there were any.
func Worst(findings []Finding) (Severity, bool) {
	if len(findings) == 0 {
		return Note, false
	}
	worst := Note
	for _, f := range findings {
		if f.Severity > worst {
			worst = f.Severity
		}
	}
	return worst, true
}

// ExitCode maps findings to a process exit status: 0 clean, 1 warnings only,
// 2 any error. Notes alone do not fail a build.
func ExitCode(findings []Finding) int {
	worst, any := Worst(findings)
	if !any {
		return 0
	}
	switch worst {
	case Error:
		return 2
	case Warning:
		return 1
	}
	return 0
}
