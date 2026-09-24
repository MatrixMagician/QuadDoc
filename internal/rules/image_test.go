package rules

import (
	"strings"
	"testing"

	"github.com/MatrixMagician/quaddoc/internal/hostctx"
)

func TestQD043(t *testing.T) {
	tests := []struct {
		name         string
		text         string
		wantFindings int
	}{
		{
			name:         "neither key is an error",
			text:         "[Container]\nExec=/bin/true\n",
			wantFindings: 1,
		},
		{
			name:         "Image= alone is fine",
			text:         "[Container]\nImage=docker.io/library/nginx:1.27\n",
			wantFindings: 0,
		},
		{
			name:         "Rootfs= alone is fine",
			text:         "[Container]\nRootfs=/var/lib/mycontainer\n",
			wantFindings: 0,
		},
		{
			name:         "an empty Rootfs= does not count, same as the generator",
			text:         "[Container]\nRootfs=\nExec=/bin/true\n",
			wantFindings: 1,
		},
		{
			name:         "both keys set is fine, even though the generator warns elsewhere",
			text:         "[Container]\nImage=nginx\nRootfs=/var/lib/mycontainer\n",
			wantFindings: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := unitFromText(t, "web.container", tt.text)
			got := runRule(t, "QD043", hostctx.Unknown{}, u)

			if len(got) != tt.wantFindings {
				t.Fatalf("findings = %d, want %d: %+v", len(got), tt.wantFindings, got)
			}
			if tt.wantFindings == 0 {
				return
			}
			if got[0].Severity != Error {
				t.Errorf("severity = %v, want Error", got[0].Severity)
			}
			if got[0].Confidence != Confirmed {
				t.Errorf("confidence = %v, want Confirmed", got[0].Confidence)
			}
		})
	}
}

func TestQD043RemediationNamesTheDecision(t *testing.T) {
	u := unitFromText(t, "web.container", "[Container]\nExec=/bin/true\n")
	got := runRule(t, "QD043", hostctx.Unknown{}, u)

	if len(got) != 1 {
		t.Fatalf("findings = %d, want 1", len(got))
	}
	if !strings.Contains(got[0].Remediation, "Image=") || !strings.Contains(got[0].Remediation, "Rootfs=") {
		t.Errorf("remediation does not name the decision: %q", got[0].Remediation)
	}
}
