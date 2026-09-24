package rules

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MatrixMagician/quaddoc/internal/hostctx"
	"github.com/MatrixMagician/quaddoc/internal/ir"
	"github.com/MatrixMagician/quaddoc/internal/podmantest"
)

func TestQD042(t *testing.T) {
	tests := []struct {
		name         string
		unit         string
		text         string
		wantFindings int
		wantSeverity Severity
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
			wantFindings: 1, wantSeverity: Error, wantContains: "did you mean Volume=?",
		},
		{
			name:         "the compose spelling is a common mistake",
			unit:         "web.container",
			text:         "[Container]\nImage=nginx\nPorts=8080:80\n",
			wantFindings: 1, wantSeverity: Error, wantContains: "PublishPort=",
		},
		{
			// Podman 5.8.4: "unsupported key 'Frobnicate' in group
			// 'Container'", and no service is generated for the unit.
			name:         "an invented key is reported without a suggestion",
			unit:         "web.container",
			text:         "[Container]\nImage=nginx\nFrobnicate=yes\n",
			wantFindings: 1, wantSeverity: Error,
			wantContains: "Frobnicate= is not a Quadlet key for [Container], so the generator rejects web.container and creates no service for it",
		},
		{
			// quadlet -dryrun on Podman 5.8.4 emits frontend.service.
			name:         "ServiceName= is honoured in a container unit",
			unit:         "web.container",
			text:         "[Container]\nImage=nginx\nServiceName=frontend\n",
			wantFindings: 0,
		},
		{
			name:         "ServiceName= is honoured in a volume unit",
			unit:         "data.volume",
			text:         "[Volume]\nServiceName=data-volume\n",
			wantFindings: 0,
		},
		{
			name:         "ServiceName= is honoured in a network unit",
			unit:         "app.network",
			text:         "[Network]\nServiceName=app-net\n",
			wantFindings: 0,
		},
		{
			// The generator still honours the deprecated keys, so they
			// are not unknown, just superseded.
			name:         "a deprecated key still works and is a note",
			unit:         "web.container",
			text:         "[Container]\nImage=nginx\nRemapUsers=keep-id\n",
			wantFindings: 1, wantSeverity: Note,
			wantContains: "RemapUsers= is deprecated; the generator still honours it",
		},
		{
			name:         "VolatileTmp= is deprecated in favour of Tmpfs=",
			unit:         "web.container",
			text:         "[Container]\nImage=nginx\nVolatileTmp=true\n",
			wantFindings: 1, wantSeverity: Note,
			wantContains: "Tmpfs=/tmp",
		},
		{
			// VolatileTmp= was only ever a [Container] key.
			name:         "a deprecated key in a section that never had it is unknown",
			unit:         "demo.pod",
			text:         "[Pod]\nVolatileTmp=true\n",
			wantFindings: 1, wantSeverity: Error,
		},
		{
			// Verified against Podman 5.8.4: the generator rejects this unit
			// with "unsupported key 'image' in group 'Container'".
			name:         "keys are matched case-sensitively, as the generator does",
			unit:         "web.container",
			text:         "[Container]\nImage=nginx\nimage=nginx\n",
			wantFindings: 1, wantSeverity: Error, wantContains: "did you mean Image=?",
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
			name:         "kube unit keys are checked against the kube section",
			unit:         "app.kube",
			text:         "[Kube]\nYaml=app.yaml\nYamll=typo.yaml\n",
			wantFindings: 1, wantSeverity: Error,
			wantContains: "Yamll= is not a Quadlet key for [Kube], so the generator rejects app.kube",
		},
		{
			name:         "build unit keys are checked against the build section",
			unit:         "img.build",
			text:         "[Build]\nImageTag=localhost/img:1\nFil=Containerfile\n",
			wantFindings: 1, wantSeverity: Error,
			wantContains: "Fil= is not a Quadlet key for [Build]",
		},
		{
			name:         "image and artifact units are checked too",
			unit:         "blob.artifact",
			text:         "[Artifact]\nArtifact=quay.io/example/blob:1\nImage=x\n",
			wantFindings: 1, wantSeverity: Error,
		},
		{
			name:         "a container key in a volume unit is wrong",
			unit:         "data.volume",
			text:         "[Volume]\nVolumeName=data\nPublishPort=80:80\n",
			wantFindings: 1, wantSeverity: Error,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := unitFromText(t, tt.unit, tt.text)
			got := runRule(t, "QD042", hostctx.Unknown{}, u)

			if len(got) != tt.wantFindings {
				t.Fatalf("findings = %d, want %d: %+v", len(got), tt.wantFindings, got)
			}
			if tt.wantFindings > 0 && got[0].Severity != tt.wantSeverity {
				t.Errorf("severity = %v, want %v", got[0].Severity, tt.wantSeverity)
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

// TestQD042MatchesTheGenerator pins the rule's premise to the real generator:
// it rejects a unit carrying a key outside its section's table, and accepts
// the keys QD042 lets through, deprecated ones included.
func TestQD042MatchesTheGenerator(t *testing.T) {
	generator := podmantest.Generator(t)

	rejected := t.TempDir()
	writeUnit(t, rejected, "web.container", "[Container]\nImage=docker.io/library/nginx:1.27\nFrobnicate=yes\n")
	cmd := exec.Command(generator, "-dryrun", "-user")
	cmd.Env = append(os.Environ(), "QUADLET_UNIT_DIRS="+rejected)
	out, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "unsupported key 'Frobnicate' in group 'Container'") {
		t.Errorf("expected the generator to reject the unknown key, got err=%v:\n%s", err, out)
	}

	accepted := map[string]string{
		"web.container": "[Container]\nImage=docker.io/library/nginx:1.27\nServiceName=frontend\n" +
			"RemapUsers=manual\nRemapUid=0:1000:1\nRemapGid=0:1000:1\nVolatileTmp=true\n",
		"data.volume":   "[Volume]\nServiceName=data-volume\n",
		"app.network":   "[Network]\nServiceName=app-net\n",
		"demo.pod":      "[Pod]\nServiceName=demo-pod\nRemapUsers=auto\nRemapUidSize=100\n",
		"app.kube":      "[Kube]\nYaml=/dev/null\nServiceName=app-kube\nRemapUsers=keep-id\nLogOpt=tag=app\n",
		"img.build":     "[Build]\nImageTag=localhost/img:1\nFile=/dev/null\nServiceName=img-build\n",
		"base.image":    "[Image]\nImage=docker.io/library/busybox:1\nServiceName=base-image\n",
		"blob.artifact": "[Artifact]\nArtifact=quay.io/example/blob:1\nServiceName=blob-artifact\n",
	}
	dir := t.TempDir()
	var units []*ir.Unit
	for name, text := range accepted {
		writeUnit(t, dir, name, text)
		units = append(units, unitFromText(t, name, text))
	}
	podmantest.AssertAccepts(t, generator, dir)

	for _, f := range runRule(t, "QD042", hostctx.Unknown{}, units...) {
		if f.Severity != Note {
			t.Errorf("the generator accepts %s, but QD042 reports it as %v: %s", f.Unit, f.Severity, f.Message)
		}
	}
}

func writeUnit(t *testing.T, dir, name, text string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
}
