package rules

import (
	"strings"
	"testing"

	"github.com/MatrixMagician/quaddoc/internal/hostctx"
)

func TestParseImageRef(t *testing.T) {
	tests := []struct {
		image        string
		wantRegistry string
		wantTag      string
		wantDigest   bool
	}{
		{image: "docker.io/library/nginx:1.27", wantRegistry: "docker.io", wantTag: "1.27"},
		{image: "quay.io/podman/stable:latest", wantRegistry: "quay.io", wantTag: "latest"},
		{image: "nginx:1.27", wantTag: "1.27"},
		{image: "nginx", wantTag: ""},
		{image: "library/nginx:1.27", wantTag: "1.27"}, // no dot, so not a registry
		{image: "localhost/mine:1", wantRegistry: "localhost", wantTag: "1"},
		{image: "registry:5000/app:1", wantRegistry: "registry:5000", wantTag: "1"},
		{
			image:        "docker.io/library/nginx@sha256:abc",
			wantRegistry: "docker.io", wantDigest: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.image, func(t *testing.T) {
			got := parseImageRef(tt.image)
			if got.Registry != tt.wantRegistry {
				t.Errorf("registry = %q, want %q", got.Registry, tt.wantRegistry)
			}
			if got.Tag != tt.wantTag {
				t.Errorf("tag = %q, want %q", got.Tag, tt.wantTag)
			}
			if got.Digest != tt.wantDigest {
				t.Errorf("digest = %v, want %v", got.Digest, tt.wantDigest)
			}
		})
	}
}

func TestQD040(t *testing.T) {
	tests := []struct {
		name         string
		text         string
		wantFindings int
		wantSeverity Severity
		wantContains string
	}{
		{
			name:         "fully qualified with a pinned tag is fine",
			text:         "[Container]\nImage=docker.io/library/nginx:1.27\nAutoUpdate=registry\n",
			wantFindings: 0,
		},
		{
			// The generator itself warns on short names, observed on 5.8.4.
			name:         "a short name with auto-update is an error",
			text:         "[Container]\nImage=nginx:1.27\nAutoUpdate=registry\n",
			wantFindings: 1, wantSeverity: Error, wantContains: "no registry",
		},
		{
			name:         "a digest with auto-update can never update",
			text:         "[Container]\nImage=docker.io/library/nginx@sha256:abc\nAutoUpdate=registry\n",
			wantFindings: 1, wantSeverity: Warning, wantContains: "digest",
		},
		{
			name:         "a floating tag with auto-update is a warning",
			text:         "[Container]\nImage=docker.io/library/nginx:latest\nAutoUpdate=registry\n",
			wantFindings: 1, wantSeverity: Warning, wantContains: "floating tag",
		},
		{
			name:         "a short name without auto-update is only a note",
			text:         "[Container]\nImage=nginx:1.27\n",
			wantFindings: 1, wantSeverity: Note,
		},
		{
			name:         "AutoUpdate=local does not require qualification",
			text:         "[Container]\nImage=docker.io/library/nginx:latest\nAutoUpdate=local\n",
			wantFindings: 0,
		},
		{
			name:         "a .image unit reference is resolved by the generator",
			text:         "[Container]\nImage=base.image\nAutoUpdate=registry\n",
			wantFindings: 0,
		},
		{
			name:         "a floating tag without auto-update is not reported here",
			text:         "[Container]\nImage=docker.io/library/nginx:latest\n",
			wantFindings: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := unitFromText(t, "web.container", tt.text)
			got := runRule(t, "QD040", hostctx.Unknown{}, u)

			if len(got) != tt.wantFindings {
				t.Fatalf("findings = %d, want %d: %+v", len(got), tt.wantFindings, got)
			}
			if tt.wantFindings == 0 {
				return
			}
			if got[0].Severity != tt.wantSeverity {
				t.Errorf("severity = %v, want %v", got[0].Severity, tt.wantSeverity)
			}
			if tt.wantContains != "" && !strings.Contains(got[0].Message, tt.wantContains) {
				t.Errorf("message %q does not mention %q", got[0].Message, tt.wantContains)
			}
		})
	}
}

func TestQD040CitesTheImageLine(t *testing.T) {
	u := unitFromText(t, "web.container",
		"[Container]\n# a comment\nImage=nginx:1.27\nAutoUpdate=registry\n")
	got := runRule(t, "QD040", hostctx.Unknown{}, u)

	if len(got) != 1 {
		t.Fatalf("findings = %d, want 1", len(got))
	}
	if got[0].Line != 3 {
		t.Errorf("line = %d, want 3", got[0].Line)
	}
}

func TestQD041(t *testing.T) {
	tests := []struct {
		name         string
		text         string
		wantFindings int
	}{
		{
			name:         "a literal password is reported",
			text:         "[Container]\nImage=postgres\nEnvironment=POSTGRES_PASSWORD=hunter2\n",
			wantFindings: 1,
		},
		{
			name:         "an API token is reported",
			text:         "[Container]\nImage=app\nEnvironment=STRIPE_API_KEY=sk_live_abc123\n",
			wantFindings: 1,
		},
		{
			// Silence on references is the point: a false positive trains
			// users to ignore the tool.
			name:         "a shell-style reference is not a leak",
			text:         "[Container]\nImage=app\nEnvironment=API_TOKEN=${API_TOKEN}\n",
			wantFindings: 0,
		},
		{
			name:         "a bare variable reference is not a leak",
			text:         "[Container]\nImage=app\nEnvironment=API_TOKEN=$API_TOKEN\n",
			wantFindings: 0,
		},
		{
			name:         "a systemd specifier is not a leak",
			text:         "[Container]\nImage=app\nEnvironment=API_TOKEN=%i\n",
			wantFindings: 0,
		},
		{
			name:         "an obvious placeholder is not reported",
			text:         "[Container]\nImage=app\nEnvironment=DB_PASSWORD=changeme\n",
			wantFindings: 0,
		},
		{
			name:         "an empty value is not reported",
			text:         "[Container]\nImage=app\nEnvironment=DB_PASSWORD=\n",
			wantFindings: 0,
		},
		{
			name:         "a non-credential variable is not reported",
			text:         "[Container]\nImage=app\nEnvironment=LOG_LEVEL=debug\n",
			wantFindings: 0,
		},
		{
			name:         "a variable merely containing 'key' is not reported",
			text:         "[Container]\nImage=app\nEnvironment=KEYBOARD_LAYOUT=gb\n",
			wantFindings: 0,
		},
		{
			name:         "several credentials on one line are each reported",
			text:         "[Container]\nImage=app\nEnvironment=DB_PASSWORD=abc API_TOKEN=xyz\n",
			wantFindings: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := unitFromText(t, "app.container", tt.text)
			got := runRule(t, "QD041", hostctx.Unknown{}, u)

			if len(got) != tt.wantFindings {
				t.Fatalf("findings = %d, want %d: %+v", len(got), tt.wantFindings, got)
			}
		})
	}
}

func TestQD041RemediationNamesTheVariable(t *testing.T) {
	// A remediation the user can paste has to name their actual variable.
	u := unitFromText(t, "db.container",
		"[Container]\nImage=postgres\nEnvironment=POSTGRES_PASSWORD=hunter2\n")
	got := runRule(t, "QD041", hostctx.Unknown{}, u)

	if len(got) != 1 {
		t.Fatalf("findings = %d, want 1", len(got))
	}
	if !strings.Contains(got[0].Remediation, "POSTGRES_PASSWORD") ||
		!strings.Contains(got[0].Remediation, "Secret=") {
		t.Errorf("remediation is not actionable: %q", got[0].Remediation)
	}
}
