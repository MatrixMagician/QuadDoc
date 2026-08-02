package rules

import (
	"strings"
	"testing"

	"github.com/MatrixMagician/quaddoc/internal/hostctx"
)

func TestQD042(t *testing.T) {
	tests := []struct {
		name         string
		unit         string
		text         string
		wantFindings int
		wantContains string
	}{
		{
			name:         "a real key is accepted",
			unit:         "web.container",
			text:         "[Container]\nImage=nginx\nVolume=/srv:/data\nPublishPort=8080:80\n",
			wantFindings: 0,
		},
		{
			name:         "the podman flag spelling is a common mistake",
			unit:         "web.container",
			text:         "[Container]\nImage=nginx\nVolumes=/srv:/data\n",
			wantFindings: 1, wantContains: "did you mean Volume=?",
		},
		{
			name:         "the compose spelling is a common mistake",
			unit:         "web.container",
			text:         "[Container]\nImage=nginx\nPorts=8080:80\n",
			wantFindings: 1, wantContains: "PublishPort=",
		},
		{
			name:         "an invented key is reported without a suggestion",
			unit:         "web.container",
			text:         "[Container]\nImage=nginx\nFrobnicate=yes\n",
			wantFindings: 1, wantContains: "will be ignored",
		},
		{
			name:         "keys are matched case-insensitively, as systemd does",
			unit:         "web.container",
			text:         "[Container]\nimage=nginx\nvolume=/srv:/data\n",
			wantFindings: 0,
		},
		{
			// [Unit], [Service], and [Install] pass straight through to
			// systemd, so their keys are not Quadlet's to validate.
			name: "systemd sections are not checked here",
			unit: "web.container",
			text: "[Unit]\nDescription=x\nAfter=y.service\n[Container]\nImage=nginx\n" +
				"[Service]\nRestart=always\nTimeoutStartSec=90\n",
			wantFindings: 0,
		},
		{
			name:         "volume unit keys are checked against the volume section",
			unit:         "data.volume",
			text:         "[Volume]\nVolumeName=data\nDriver=local\n",
			wantFindings: 0,
		},
		{
			name:         "a container key in a volume unit is wrong",
			unit:         "data.volume",
			text:         "[Volume]\nVolumeName=data\nPublishPort=80:80\n",
			wantFindings: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := unitFromText(t, tt.unit, tt.text)
			got := runRule(t, "QD042", hostctx.Unknown{}, u)

			if len(got) != tt.wantFindings {
				t.Fatalf("findings = %d, want %d: %+v", len(got), tt.wantFindings, got)
			}
			if tt.wantContains != "" &&
				!strings.Contains(got[0].Message, tt.wantContains) &&
				!strings.Contains(got[0].Remediation, tt.wantContains) {
				t.Errorf("neither message nor remediation mentions %q: %+v", tt.wantContains, got[0])
			}
		})
	}
}

func TestKnownKeysWereGenerated(t *testing.T) {
	// A hand-edited table is the failure mode ADR-0002 exists to avoid, so
	// this asserts the table looks like the generator's output rather than
	// something typed by hand.
	if len(knownKeys) < 4 {
		t.Fatalf("knownKeys covers %d sections, expected at least Container, Pod, Network, Volume",
			len(knownKeys))
	}
	if generatedFromPodman == "" {
		t.Error("the key set does not record which Podman release it came from")
	}

	// Spot-check keys verified by hand against podman-systemd.unit(5).
	for _, want := range []struct{ Section, Key string }{
		{"Container", "HealthStartPeriod"},
		{"Container", "Notify"},
		{"Container", "GroupAdd"},
		{"Container", "AutoUpdate"},
		{"Volume", "VolumeName"},
		{"Network", "NetworkName"},
		{"Pod", "PodName"},
	} {
		if !knownKeys[want.Section][want.Key] {
			t.Errorf("knownKeys[%s] is missing %s", want.Section, want.Key)
		}
	}
}

func TestQD042NamesThePodmanItCheckedAgainst(t *testing.T) {
	// A user on a newer Podman needs to know the finding may be stale.
	u := unitFromText(t, "web.container", "[Container]\nImage=nginx\nFrobnicate=yes\n")

	got := runRule(t, "QD042", hostctx.Unknown{}, u)
	if len(got) != 1 {
		t.Fatalf("findings = %d, want 1", len(got))
	}
	if !strings.Contains(got[0].Remediation, generatedFromPodman) {
		t.Errorf("remediation does not say which Podman the key set came from:\n%s",
			got[0].Remediation)
	}
}
