package output

import (
	"encoding/json"
	"io"
	"net/url"
	"strings"

	"github.com/MatrixMagician/quaddoc/internal/rules"
)

// SARIF is how findings reach GitHub code scanning and similar tools, which is
// the realistic way a team adopts a linter: it appears in the pull request
// rather than in a log nobody reads.
//
// The schema is SARIF 2.1.0, an OASIS standard.
const (
	sarifVersion = "2.1.0"
	sarifSchema  = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
)

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Version        string      `json:"version,omitempty"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID                   string          `json:"id"`
	Name                 string          `json:"name"`
	ShortDescription     sarifText       `json:"shortDescription"`
	FullDescription      sarifText       `json:"fullDescription"`
	Help                 sarifText       `json:"help"`
	DefaultConfiguration sarifRuleConfig `json:"defaultConfiguration"`
	Properties           sarifRuleProps  `json:"properties,omitempty"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifRuleConfig struct {
	Level string `json:"level"`
}

type sarifRuleProps struct {
	Tags []string `json:"tags,omitempty"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	RuleIndex int             `json:"ruleIndex"`
	Level     string          `json:"level"`
	Message   sarifText       `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           *sarifRegion  `json:"region,omitempty"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

// sarifLevel maps a severity onto SARIF's vocabulary. SARIF has no "note that
// is really a warning", so the mapping is direct.
func sarifLevel(s rules.Severity) string {
	switch s {
	case rules.Error:
		return "error"
	case rules.Warning:
		return "warning"
	}
	return "note"
}

// SARIF writes findings in SARIF 2.1.0.
//
// Every registered rule is declared, not only those that fired, so that a
// consumer can show the full catalogue and so that a rule going quiet between
// runs does not look like the rule disappearing.
func SARIF(w io.Writer, findings []rules.Finding, version string) error {
	all := rules.All()

	index := make(map[string]int, len(all))
	declared := make([]sarifRule, 0, len(all))
	for i, r := range all {
		index[r.ID] = i
		declared = append(declared, sarifRule{
			ID:               r.ID,
			Name:             r.ID,
			ShortDescription: sarifText{Text: r.Summary},
			FullDescription:  sarifText{Text: r.Rationale},
			// The citation is the rule's justification, so it belongs in the
			// help text where a reviewer meeting the rule will read it.
			Help:                 sarifText{Text: r.Rationale + "\n\nSource: " + r.Citation},
			DefaultConfiguration: sarifRuleConfig{Level: sarifLevel(r.DefaultSeverity)},
			Properties:           sarifRuleProps{Tags: sarifTags(r)},
		})
	}

	results := make([]sarifResult, 0, len(findings))
	for _, f := range findings {
		i, known := index[f.RuleID]
		if !known {
			continue
		}

		result := sarifResult{
			RuleID:    f.RuleID,
			RuleIndex: i,
			Level:     sarifLevel(f.Severity),
			// The remediation belongs in the message: a reviewer looking at
			// an annotation in a pull request wants to know what to do, not
			// merely what is wrong.
			Message: sarifText{Text: f.Message + "\n\n" + f.Remediation},
			Locations: []sarifLocation{{
				PhysicalLocation: sarifPhysicalLocation{
					ArtifactLocation: sarifArtifact{URI: artifactURI(f.Unit)},
				},
			}},
		}
		if f.Line > 0 {
			result.Locations[0].PhysicalLocation.Region = &sarifRegion{StartLine: f.Line}
		}
		results = append(results, result)
	}

	log := sarifLog{
		Schema:  sarifSchema,
		Version: sarifVersion,
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "quaddoc",
				InformationURI: "https://github.com/MatrixMagician/QuadDoc",
				Version:        version,
				Rules:          declared,
			}},
			Results: results,
		}},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

// sarifTags groups rules by family, so a consumer can filter.
func sarifTags(r *rules.Rule) []string {
	var tags []string
	switch {
	case r.ID >= "QD001" && r.ID <= "QD009":
		tags = append(tags, "selinux")
	case r.ID >= "QD010" && r.ID <= "QD019":
		tags = append(tags, "rootless")
	case r.ID >= "QD020" && r.ID <= "QD029":
		tags = append(tags, "lifecycle")
	case r.ID >= "QD030" && r.ID <= "QD039":
		tags = append(tags, "networking")
	case r.ID >= "QD040":
		tags = append(tags, "hygiene")
	}
	if r.Fixable {
		tags = append(tags, "fixable")
	}
	if r.NeedsHostContext {
		tags = append(tags, "host-context")
	}
	return tags
}

// artifactURI renders a path as a SARIF artifact location. SARIF wants a URI
// reference, and a relative path is both valid and more useful in CI, where the
// absolute path is a temporary checkout directory.
func artifactURI(path string) string {
	cleaned := strings.TrimPrefix(path, "./")
	return (&url.URL{Path: cleaned}).String()
}
