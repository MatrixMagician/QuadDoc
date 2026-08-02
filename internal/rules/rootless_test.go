package rules

import (
	"strings"
	"testing"

	"github.com/MatrixMagician/quaddoc/internal/hostctx"
	"github.com/MatrixMagician/quaddoc/internal/ir"
)

// rootlessHost matches the reference platform: rootless Podman with the
// subordinate ranges Fedora allocates by default.
var rootlessHost = hostctx.Static{
	SELinuxMode:   hostctx.SELinuxEnforcing,
	SubUID:        []hostctx.IDRange{{Start: 524288, Count: 65536}},
	SubGID:        []hostctx.IDRange{{Start: 524288, Count: 65536}},
	IsRootless:    true,
	RootlessKnown: true,
}

// TestQD012StaysSilentOnTheCommonCase is the regression test for finding F1.
//
// The spec said to warn whenever a non-root image mounts a named volume with no
// chown strategy. That is wrong: Podman chowns a named volume's mount point on
// first use, which was reproduced during the spec review:
//
//	$ podman volume create qdtest
//	$ podman run --rm --user 1234:1234 -v qdtest:/data alpine ls -ldn /data
//	drwxr-xr-x 1 1234 1234 0 /data
//
// Shipping the rule as specified would have fired on the correct case, which is
// the most damaging kind of finding for a linter whose value is being trusted.
func TestQD012StaysSilentOnTheCommonCase(t *testing.T) {
	volume := unitFromText(t, "pgdata.volume", "[Volume]\n")
	app := unitFromText(t, "app.container",
		"[Container]\nImage=postgres\nUser=1234\nVolume=pgdata.volume:/var/lib/postgresql/data\n")

	got := runRule(t, "QD012", rootlessHost, volume, app)
	if len(got) != 0 {
		t.Errorf("QD012 fired on a fresh volume with a non-root user, which Podman "+
			"chowns automatically. This is the F1 false positive: %+v", got)
	}
}

func TestQD012(t *testing.T) {
	tests := []struct {
		name         string
		units        map[string]string
		wantFindings int
		wantContains string
	}{
		{
			name: "a fresh volume with a non-root user is fine",
			units: map[string]string{
				"data.volume":   "[Volume]\n",
				"app.container": "[Container]\nImage=app\nUser=1000\nVolume=data.volume:/data\n",
			},
			wantFindings: 0,
		},
		{
			name: "a root container is not affected",
			units: map[string]string{
				"data.volume":   "[Volume]\n",
				"app.container": "[Container]\nImage=app\nUser=0\nVolume=data.volume:/data\n",
			},
			wantFindings: 0,
		},
		{
			name: "no User= means the image decides, so stay silent",
			units: map[string]string{
				"data.volume":   "[Volume]\n",
				"app.container": "[Container]\nImage=app\nVolume=data.volume:/data\n",
			},
			wantFindings: 0,
		},
		{
			// Reproduced: a volume first populated by root gives Permission
			// denied to a later non-root container.
			name: "a volume shared with a container that may run as root",
			units: map[string]string{
				"data.volume":     "[Volume]\n",
				"app.container":   "[Container]\nImage=app\nUser=1000\nVolume=data.volume:/data\n",
				"admin.container": "[Container]\nImage=admin\nVolume=data.volume:/data\n",
			},
			wantFindings: 1,
			wantContains: "may populate it as root first",
		},
		{
			name: "two non-root containers with different UIDs cannot both own it",
			units: map[string]string{
				"data.volume": "[Volume]\n",
				"a.container": "[Container]\nImage=a\nUser=1000\nVolume=data.volume:/data\n",
				"b.container": "[Container]\nImage=b\nUser=2000\nVolume=data.volume:/data\n",
			},
			wantFindings: 2,
		},
		{
			// A local-driver volume with a bind device keeps the host
			// directory's ownership, so first-use chown does not save you.
			// Reproduced: writes were denied.
			name: "a bind masquerading as a named volume",
			units: map[string]string{
				"data.volume": "[Volume]\nType=none\nDevice=/srv/appdata\nOptions=bind\n",
				"app.container": "[Container]\nImage=app\nUser=1000\n" +
					"Volume=data.volume:/data\n",
			},
			wantFindings: 1,
			wantContains: "keeps that directory's ownership",
		},
		{
			name: "an explicit :U is the fix, so nothing to report",
			units: map[string]string{
				"data.volume": "[Volume]\nType=none\nDevice=/srv/appdata\nOptions=bind\n",
				"app.container": "[Container]\nImage=app\nUser=1000\n" +
					"Volume=data.volume:/data:U\n",
			},
			wantFindings: 0,
		},
		{
			name: "bind mounts are QD010's business, not this rule's",
			units: map[string]string{
				"app.container": "[Container]\nImage=app\nUser=1000\nVolume=/srv/data:/data\n",
			},
			wantFindings: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := runRule(t, "QD012", rootlessHost, namedUnits(t, tt.units)...)

			if len(got) != tt.wantFindings {
				t.Fatalf("findings = %d, want %d: %+v", len(got), tt.wantFindings, got)
			}
			if tt.wantContains != "" && !strings.Contains(got[0].Message, tt.wantContains) {
				t.Errorf("message %q does not mention %q", got[0].Message, tt.wantContains)
			}
		})
	}
}

func TestQD012RemediationWarnsAboutTheCostOfU(t *testing.T) {
	// podman-run(1) notes that chowning walks every inode, which on a large
	// volume delays startup. A remediation that omits that sets the user up
	// for a different surprise.
	units := namedUnits(t, map[string]string{
		"data.volume":     "[Volume]\n",
		"app.container":   "[Container]\nImage=app\nUser=1000\nVolume=data.volume:/data\n",
		"admin.container": "[Container]\nImage=admin\nVolume=data.volume:/data\n",
	})

	got := runRule(t, "QD012", rootlessHost, units...)
	if len(got) != 1 {
		t.Fatalf("findings = %d, want 1", len(got))
	}
	if !strings.Contains(got[0].Remediation, ":U") {
		t.Errorf("remediation does not name :U:\n%s", got[0].Remediation)
	}
	if !strings.Contains(got[0].Remediation, "delay") {
		t.Errorf("remediation does not warn about the cost of chowning:\n%s", got[0].Remediation)
	}
}

func TestQD010(t *testing.T) {
	tests := []struct {
		name         string
		text         string
		wantFindings int
	}{
		{
			name:         "a non-root container writing to a bind mount",
			text:         "[Container]\nImage=app\nUser=1000\nVolume=/srv/data:/data\n",
			wantFindings: 1,
		},
		{
			name:         "keep-id aligns the users, so nothing to report",
			text:         "[Container]\nImage=app\nUser=1000\nUserNS=keep-id\nVolume=/srv/data:/data\n",
			wantFindings: 0,
		},
		{
			name:         ":U chowns the source, which is the other right answer",
			text:         "[Container]\nImage=app\nUser=1000\nVolume=/srv/data:/data:U\n",
			wantFindings: 0,
		},
		{
			name:         "a read-only mount usually works",
			text:         "[Container]\nImage=app\nUser=1000\nVolume=/srv/data:/data:ro\n",
			wantFindings: 0,
		},
		{
			name:         "a root container maps to the host user directly",
			text:         "[Container]\nImage=app\nUser=0\nVolume=/srv/data:/data\n",
			wantFindings: 0,
		},
		{
			name:         "no User= means the image decides",
			text:         "[Container]\nImage=app\nVolume=/srv/data:/data\n",
			wantFindings: 0,
		},
		{
			name:         "named volumes are QD012's business",
			text:         "[Container]\nImage=app\nUser=1000\nVolume=data.volume:/data\n",
			wantFindings: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := unitFromText(t, "app.container", tt.text)
			got := runRule(t, "QD010", rootlessHost, u)

			if len(got) != tt.wantFindings {
				t.Fatalf("findings = %d, want %d: %+v", len(got), tt.wantFindings, got)
			}
		})
	}
}

func TestQD010OffersBothRemedies(t *testing.T) {
	// The choice between keep-id and :U depends on who should own the files,
	// which is the user's decision, not ours. The finding must present both
	// and say when each applies.
	u := unitFromText(t, "app.container", "[Container]\nImage=app\nUser=1000\nVolume=/srv/data:/data\n")
	got := runRule(t, "QD010", rootlessHost, u)

	if len(got) != 1 {
		t.Fatalf("findings = %d, want 1", len(got))
	}
	if !strings.Contains(got[0].Remediation, "keep-id") {
		t.Errorf("remediation does not offer UserNS=keep-id:\n%s", got[0].Remediation)
	}
	if !strings.Contains(got[0].Remediation, ":U") {
		t.Errorf("remediation does not offer :U:\n%s", got[0].Remediation)
	}
}

func TestQD011(t *testing.T) {
	tests := []struct {
		name         string
		text         string
		wantFindings int
	}{
		{
			name:         "a named group will not resolve to the host group",
			text:         "[Container]\nImage=app\nGroupAdd=video\n",
			wantFindings: 1,
		},
		{
			name:         "keep-groups is the documented answer",
			text:         "[Container]\nImage=app\nGroupAdd=keep-groups\n",
			wantFindings: 0,
		},
		{
			name:         "a numeric GID means what it says inside the container",
			text:         "[Container]\nImage=app\nGroupAdd=39\n",
			wantFindings: 0,
		},
		{
			name:         "several named groups are each reported",
			text:         "[Container]\nImage=app\nGroupAdd=video\nGroupAdd=render\n",
			wantFindings: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := unitFromText(t, "app.container", tt.text)
			got := runRule(t, "QD011", rootlessHost, u)

			if len(got) != tt.wantFindings {
				t.Fatalf("findings = %d, want %d: %+v", len(got), tt.wantFindings, got)
			}
			if tt.wantFindings > 0 && !strings.Contains(got[0].Remediation, "keep-groups") {
				t.Errorf("remediation should recommend keep-groups:\n%s", got[0].Remediation)
			}
		})
	}
}

func TestQD011MentionsTheCrunRequirement(t *testing.T) {
	// podman-run(1) is explicit that keep-groups is crun-only. Recommending it
	// without saying so would send a runc user down a dead end.
	u := unitFromText(t, "app.container", "[Container]\nImage=app\nGroupAdd=video\n")
	got := runRule(t, "QD011", rootlessHost, u)

	if len(got) != 1 {
		t.Fatalf("findings = %d, want 1", len(got))
	}
	if !strings.Contains(got[0].Remediation, "crun") {
		t.Errorf("remediation does not mention the crun requirement:\n%s", got[0].Remediation)
	}
}

func TestQD013(t *testing.T) {
	// The reference box allocates 65536 subordinate IDs.
	tests := []struct {
		name         string
		text         string
		host         hostctx.Context
		wantFindings int
	}{
		{
			name:         "an ID within the range is fine",
			text:         "[Container]\nImage=app\nUser=1000\n",
			host:         rootlessHost,
			wantFindings: 0,
		},
		{
			name:         "an ID beyond the range cannot be mapped",
			text:         "[Container]\nImage=app\nUser=70000\n",
			host:         rootlessHost,
			wantFindings: 1,
		},
		{
			name:         "UID 0 always maps to the invoking user",
			text:         "[Container]\nImage=app\nUser=0\n",
			host:         rootlessHost,
			wantFindings: 0,
		},
		{
			name:         "a GID beyond the range is also reported",
			text:         "[Container]\nImage=app\nUser=1000\nGroup=70000\n",
			host:         rootlessHost,
			wantFindings: 1,
		},
		{
			name:         "without host context the rule stays silent",
			text:         "[Container]\nImage=app\nUser=70000\n",
			host:         hostctx.Unknown{},
			wantFindings: 0,
		},
		{
			name: "running as root removes the constraint",
			text: "[Container]\nImage=app\nUser=70000\n",
			host: hostctx.Static{
				SubUID:        []hostctx.IDRange{{Start: 524288, Count: 65536}},
				RootlessKnown: true, IsRootless: false,
			},
			wantFindings: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := unitFromText(t, "app.container", tt.text)
			got := runRule(t, "QD013", tt.host, u)

			if len(got) != tt.wantFindings {
				t.Fatalf("findings = %d, want %d: %+v", len(got), tt.wantFindings, got)
			}
		})
	}
}

func TestQD013IsConfirmedNotPossible(t *testing.T) {
	// The rule runs only with host context, so its findings are facts about
	// the machine rather than guesses.
	u := unitFromText(t, "app.container", "[Container]\nImage=app\nUser=70000\n")
	got := runRule(t, "QD013", rootlessHost, u)

	if len(got) != 1 {
		t.Fatalf("findings = %d, want 1", len(got))
	}
	if got[0].Confidence != Confirmed {
		t.Errorf("confidence = %v, want Confirmed", got[0].Confidence)
	}
}

// namedUnits builds units from a name-to-text map, sorted for determinism.
func namedUnits(t *testing.T, texts map[string]string) []*ir.Unit {
	t.Helper()

	names := make([]string, 0, len(texts))
	for name := range texts {
		names = append(names, name)
	}
	// Sort so the project order does not depend on map iteration.
	for i := range names {
		for j := i + 1; j < len(names); j++ {
			if names[j] < names[i] {
				names[i], names[j] = names[j], names[i]
			}
		}
	}

	units := make([]*ir.Unit, 0, len(names))
	for _, name := range names {
		units = append(units, unitFromText(t, name, texts[name]))
	}
	return units
}
