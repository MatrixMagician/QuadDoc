package rules

import (
	"fmt"
	"strings"
)

// Hygiene rules: image references and secrets.
func init() {
	Register(&Rule{
		ID:      "QD040",
		Summary: "AutoUpdate=registry needs a fully-qualified image reference",
		Rationale: "Auto-update has to know which image to check, which it cannot do from " +
			"a short name that depends on registry search order, nor from a digest that " +
			"never changes. A floating tag such as latest is also worth flagging: it " +
			"works, but combined with auto-update it means the running version is " +
			"whatever the registry served most recently.",
		Citation: "podman-systemd.unit(5), AutoUpdate=: registry \"Requires a " +
			"fully-qualified image reference (e.g., quay.io/podman/stable:latest) to be " +
			"used to create the container. This enforcement is necessary to know which " +
			"image to actually check and pull.\" The Quadlet generator itself warns on " +
			"short names (observed, Podman 5.8.4).",
		DefaultSeverity: Warning,
		Check:           checkQD040,
	})

	Register(&Rule{
		ID:      "QD041",
		Summary: "Credential passed as an environment value in the unit file",
		Rationale: "A unit file is world-readable in the Quadlet search path and is " +
			"usually committed to version control, so a credential in Environment= is " +
			"exposed twice over. Podman secrets keep the value out of the unit and out " +
			"of the container's environment listing.",
		Citation: "podman-systemd.unit(5), Secret=: \"Use a Podman secret in the container " +
			"either as a file or an environment variable.\" It is the Quadlet spelling of " +
			"podman-run(1)'s --secret.",
		DefaultSeverity: Warning,
		Check:           checkQD041,
	})
}

// knownRegistries are hostnames we recognise without needing a dot or a port,
// so that `localhost/foo` is not reported as a short name.
var knownRegistries = map[string]bool{
	"localhost": true,
}

// floatingTags never pin a version, so the image a container runs can change
// under it.
var floatingTags = map[string]bool{
	"latest":  true,
	"stable":  true,
	"edge":    true,
	"main":    true,
	"master":  true,
	"devel":   true,
	"nightly": true,
}

// imageRef is a decomposed image reference.
type imageRef struct {
	// Registry is the hostname, empty when the reference is a short name.
	Registry string
	// Tag is the tag, empty when the reference is untagged or uses a digest.
	Tag string
	// Digest is set when the reference pins a digest.
	Digest bool
}

// parseImageRef decomposes an image reference.
//
// A leading component is a registry when it contains a dot or a colon, or is a
// recognised name such as `localhost`. That is the same heuristic the container
// tooling uses to tell `example.com/foo` from `library/foo`.
func parseImageRef(image string) imageRef {
	var ref imageRef

	rest := image
	if i := strings.Index(rest, "@"); i >= 0 {
		ref.Digest = true
		rest = rest[:i]
	}

	first, remainder, hasSlash := strings.Cut(rest, "/")
	if hasSlash && (strings.ContainsAny(first, ".:") || knownRegistries[first]) {
		ref.Registry = first
		rest = remainder
	}

	// A colon after the final slash introduces the tag.
	if i := strings.LastIndex(rest, ":"); i >= 0 && !strings.Contains(rest[i:], "/") {
		ref.Tag = rest[i+1:]
	}
	return ref
}

func checkQD040(c *Context) []Finding {
	var findings []Finding

	for _, u := range c.Project.Containers() {
		if u.Image == "" {
			continue
		}
		// A Quadlet .image or .build unit reference is resolved by the
		// generator, not by a registry, so registry rules do not apply.
		if strings.HasSuffix(u.Image, ".image") || strings.HasSuffix(u.Image, ".build") {
			continue
		}

		ref := parseImageRef(u.Image)
		autoUpdate := lower(u.AutoUpdate)
		line := u.KeyLine("Image")

		if autoUpdate == "registry" {
			switch {
			case ref.Registry == "":
				findings = append(findings, Finding{
					Severity:   Error,
					Confidence: Confirmed,
					Unit:       u.Path,
					Line:       line,
					Message: fmt.Sprintf("AutoUpdate=registry needs a fully-qualified image, but %q has no registry",
						u.Image),
					Remediation: fmt.Sprintf("Qualify the image, for example:\n\n    Image=docker.io/%s\n\n"+
						"Auto-update cannot resolve a short name, because which registry it "+
						"means depends on the host's search order.", u.Image),
				})
			case ref.Digest:
				findings = append(findings, Finding{
					Severity:   Warning,
					Confidence: Confirmed,
					Unit:       u.Path,
					Line:       line,
					Message: fmt.Sprintf("AutoUpdate=registry has nothing to do for %q, which is pinned to a digest",
						u.Image),
					Remediation: "A digest names one immutable image, so auto-update will never " +
						"find a newer one. Either use a tag, or drop AutoUpdate=registry.",
				})
			case floatingTags[ref.Tag]:
				findings = append(findings, Finding{
					Severity:   Warning,
					Confidence: Confirmed,
					Unit:       u.Path,
					Line:       line,
					Message: fmt.Sprintf("AutoUpdate=registry with the floating tag %q means the running version is whatever the registry served last",
						ref.Tag),
					Remediation: "This combination works, but nothing records which version is " +
						"running. Pin a version tag if you need to know what you are " +
						"deploying, or keep the floating tag deliberately.",
				})
			}
			continue
		}

		// Without auto-update a short name is still a reproducibility
		// problem, and the generator warns about it too, but it is milder.
		if ref.Registry == "" {
			findings = append(findings, Finding{
				Severity:   Note,
				Confidence: Confirmed,
				Unit:       u.Path,
				Line:       line,
				Message: fmt.Sprintf("image %q has no registry, so which one it means depends on the host's search order",
					u.Image),
				Remediation: fmt.Sprintf("Qualify the image, for example:\n\n    Image=docker.io/%s", u.Image),
			})
		}
	}
	return findings
}

// credentialSuffixes name environment variables that conventionally hold a
// secret. Matching is deliberately narrow: a false positive here trains users
// to ignore the tool, which costs more than a missed finding.
var credentialSuffixes = []string{
	"_PASSWORD", "_PASSWD", "_SECRET", "_TOKEN", "_API_KEY", "_APIKEY",
	"_PRIVATE_KEY", "_ACCESS_KEY", "_SECRET_KEY", "_CREDENTIALS",
}

// credentialNames are whole names that hold a secret.
var credentialNames = map[string]bool{
	"PASSWORD": true, "PASSWD": true, "SECRET": true, "TOKEN": true,
}

// placeholders are values that obviously carry no real credential, so
// reporting them would be noise.
var placeholders = map[string]bool{
	"": true, "changeme": true, "change_me": true, "password": true,
	"secret": true, "example": true, "placeholder": true, "todo": true,
	"xxx": true, "yyy": true, "none": true, "null": true, "unset": true,
}

// looksLikeCredential reports whether an environment variable name suggests it
// holds a secret.
func looksLikeCredential(name string) bool {
	upper := strings.ToUpper(name)
	if credentialNames[upper] {
		return true
	}
	for _, suffix := range credentialSuffixes {
		if strings.HasSuffix(upper, suffix) {
			return true
		}
	}
	return false
}

// isLiteralSecret reports whether a value is a real credential rather than a
// reference to one or an obvious placeholder.
func isLiteralSecret(value string) bool {
	v := strings.TrimSpace(value)
	if placeholders[strings.ToLower(v)] {
		return false
	}
	// A reference to something resolved elsewhere is not a leak: systemd
	// specifiers (%i), shell-style expansions (${VAR}, $VAR), and Podman
	// secret references all defer the value.
	if strings.HasPrefix(v, "$") || strings.HasPrefix(v, "%") {
		return false
	}
	if strings.Contains(v, "${") {
		return false
	}
	return true
}

func checkQD041(c *Context) []Finding {
	var findings []Finding

	for _, u := range c.Project.Units {
		for _, env := range u.Environment {
			if !looksLikeCredential(env.Name) || !isLiteralSecret(env.Value) {
				continue
			}
			findings = append(findings, Finding{
				Severity:   Warning,
				Confidence: Confirmed,
				Unit:       u.Path,
				Line:       env.Line,
				Message: fmt.Sprintf("%s= holds a literal credential in the unit file",
					env.Name),
				Remediation: fmt.Sprintf("Move the value into a Podman secret and reference it:\n\n"+
					"    printf '%%s' \"$VALUE\" | podman secret create %s -\n\n"+
					"then in the unit:\n\n"+
					"    Secret=%s,type=env,target=%s\n\n"+
					"and remove the Environment= line.",
					strings.ToLower(env.Name), strings.ToLower(env.Name), env.Name),
			})
		}
	}
	return findings
}
