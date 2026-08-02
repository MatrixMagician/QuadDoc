package rules

import (
	"strings"
	"testing"

	"github.com/MatrixMagician/quaddoc/internal/hostctx"
)

func TestQD030(t *testing.T) {
	tests := []struct {
		name         string
		units        map[string]string
		wantFindings int
	}{
		{
			name: "two containers on the default network cannot resolve each other",
			units: map[string]string{
				"web.container": "[Container]\nImage=nginx\n",
				"db.container":  "[Container]\nImage=postgres\n",
			},
			wantFindings: 2,
		},
		{
			name: "a shared network unit fixes it",
			units: map[string]string{
				"app.network":   "[Network]\n",
				"web.container": "[Container]\nImage=nginx\nNetwork=app.network\n",
				"db.container":  "[Container]\nImage=postgres\nNetwork=app.network\n",
			},
			wantFindings: 0,
		},
		{
			name: "one container has no siblings to resolve",
			units: map[string]string{
				"web.container": "[Container]\nImage=nginx\n",
			},
			wantFindings: 0,
		},
		{
			// ADR-0001: pod members share a namespace and use localhost.
			name: "pod members are exempt",
			units: map[string]string{
				"stack.pod":     "[Pod]\nPodName=stack\n[Install]\nWantedBy=default.target\n",
				"web.container": "[Container]\nImage=nginx\nPod=stack.pod\n",
				"db.container":  "[Container]\nImage=postgres\nPod=stack.pod\n",
			},
			wantFindings: 0,
		},
		{
			name: "host networking is a deliberate choice",
			units: map[string]string{
				"web.container": "[Container]\nImage=nginx\nNetwork=host\n",
				"db.container":  "[Container]\nImage=postgres\nNetwork=host\n",
			},
			wantFindings: 0,
		},
		{
			name: "one container on a network, one not",
			units: map[string]string{
				"app.network":   "[Network]\n",
				"web.container": "[Container]\nImage=nginx\nNetwork=app.network\n",
				"db.container":  "[Container]\nImage=postgres\n",
			},
			wantFindings: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := runRule(t, "QD030", hostctx.Unknown{}, namedUnits(t, tt.units)...)
			if len(got) != tt.wantFindings {
				t.Fatalf("findings = %d, want %d: %+v", len(got), tt.wantFindings, got)
			}
		})
	}
}

func TestQD030RemediationIsAWholeUnitFile(t *testing.T) {
	// The user has to create a file that does not exist yet, so the
	// remediation must contain the whole thing, not a fragment.
	units := namedUnits(t, map[string]string{
		"web.container": "[Container]\nImage=nginx\n",
		"db.container":  "[Container]\nImage=postgres\n",
	})

	got := runRule(t, "QD030", hostctx.Unknown{}, units...)
	if len(got) == 0 {
		t.Fatal("expected findings")
	}
	for _, want := range []string{"[Network]", "NetworkName=", "[Install]", "Network="} {
		if !strings.Contains(got[0].Remediation, want) {
			t.Errorf("remediation is missing %q:\n%s", want, got[0].Remediation)
		}
	}
}

func TestQD031(t *testing.T) {
	tests := []struct {
		name         string
		text         string
		threshold    int
		knowsHost    bool
		wantFindings int
	}{
		{
			name:      "port 80 is below the default threshold",
			text:      "[Container]\nImage=nginx\nPublishPort=80:80\n",
			threshold: 1024, knowsHost: true, wantFindings: 1,
		},
		{
			name:      "port 8080 is fine",
			text:      "[Container]\nImage=nginx\nPublishPort=8080:80\n",
			threshold: 1024, knowsHost: true, wantFindings: 0,
		},
		{
			// The threshold is a sysctl, not a constant. An administrator who
			// lowered it to 80 should get no finding for port 80.
			name:      "a lowered threshold is respected",
			text:      "[Container]\nImage=nginx\nPublishPort=80:80\n",
			threshold: 80, knowsHost: true, wantFindings: 0,
		},
		{
			name:      "a raised threshold catches more ports",
			text:      "[Container]\nImage=nginx\nPublishPort=2000:80\n",
			threshold: 4096, knowsHost: true, wantFindings: 1,
		},
		{
			name:      "a container port with no host port binds nothing privileged",
			text:      "[Container]\nImage=nginx\nPublishPort=80\n",
			threshold: 1024, knowsHost: true, wantFindings: 0,
		},
		{
			name:      "without host context the kernel default is assumed",
			text:      "[Container]\nImage=nginx\nPublishPort=80:80\n",
			knowsHost: false, wantFindings: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var host hostctx.Context = hostctx.Unknown{}
			if tt.knowsHost {
				host = hostctx.Static{
					PortStart: tt.threshold, PortStartKnown: true,
					IsRootless: true, RootlessKnown: true,
				}
			}

			u := unitFromText(t, "web.container", tt.text)
			got := runRule(t, "QD031", host, u)

			if len(got) != tt.wantFindings {
				t.Fatalf("findings = %d, want %d: %+v", len(got), tt.wantFindings, got)
			}
			if tt.wantFindings > 0 && tt.knowsHost && got[0].Confidence != Confirmed {
				t.Errorf("with host context the finding should be confirmed, got %v", got[0].Confidence)
			}
			if tt.wantFindings > 0 && !tt.knowsHost && got[0].Confidence != Possible {
				t.Errorf("without host context the finding should be possible, got %v", got[0].Confidence)
			}
		})
	}
}

func TestQD031SilentWhenRootful(t *testing.T) {
	// A rootful Podman binds low ports freely, so the rule has nothing to say.
	host := hostctx.Static{
		PortStart: 1024, PortStartKnown: true,
		IsRootless: false, RootlessKnown: true,
	}
	u := unitFromText(t, "web.container", "[Container]\nImage=nginx\nPublishPort=80:80\n")

	if got := runRule(t, "QD031", host, u); len(got) != 0 {
		t.Errorf("QD031 fired for a rootful host: %+v", got)
	}
}

func TestQD032(t *testing.T) {
	host := hostctx.Static{
		UnitNames:      []string{"web.container", "shared.network"},
		UnitNamesKnown: true,
	}

	tests := []struct {
		name         string
		unit         string
		text         string
		wantFindings int
	}{
		{name: "a colliding container name", unit: "web.container", text: "[Container]\nImage=nginx\n", wantFindings: 1},
		{name: "a colliding network name", unit: "shared.network", text: "[Network]\n", wantFindings: 1},
		{name: "a free name", unit: "api.container", text: "[Container]\nImage=api\n", wantFindings: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := unitFromText(t, tt.unit, tt.text)
			got := runRule(t, "QD032", host, u)

			if len(got) != tt.wantFindings {
				t.Fatalf("findings = %d, want %d: %+v", len(got), tt.wantFindings, got)
			}
		})
	}
}

func TestQD032MentionsTheSystemdPrefix(t *testing.T) {
	// Quadlet names the objects it creates `systemd-<name>`, so a rename
	// changes the object name too. A user who does not know that will be
	// surprised twice.
	host := hostctx.Static{UnitNames: []string{"web.container"}, UnitNamesKnown: true}
	u := unitFromText(t, "web.container", "[Container]\nImage=nginx\n")

	got := runRule(t, "QD032", host, u)
	if len(got) != 1 {
		t.Fatalf("findings = %d, want 1", len(got))
	}
	if !strings.Contains(got[0].Remediation, "systemd-web") {
		t.Errorf("remediation does not mention the systemd- prefix:\n%s", got[0].Remediation)
	}
}

func TestQD032NeedsHostContext(t *testing.T) {
	u := unitFromText(t, "web.container", "[Container]\nImage=nginx\n")
	if got := runRule(t, "QD032", hostctx.Unknown{}, u); len(got) != 0 {
		t.Errorf("QD032 fired without host context: %+v", got)
	}
}

func TestQD020(t *testing.T) {
	tests := []struct {
		name         string
		units        map[string]string
		wantFindings int
		wantContains string
	}{
		{
			name: "ordering after a container is not a readiness gate",
			units: map[string]string{
				"web.container": "[Unit]\nAfter=db.service\n[Container]\nImage=nginx\n",
				"db.container":  "[Container]\nImage=postgres\n",
			},
			wantFindings: 1,
			wantContains: "not to become ready",
		},
		{
			name: "Notify=healthy on the dependency closes the gap",
			units: map[string]string{
				"web.container": "[Unit]\nAfter=db.service\n[Container]\nImage=nginx\n",
				"db.container":  "[Container]\nImage=postgres\nNotify=healthy\nHealthCmd=pg_isready\n",
			},
			wantFindings: 0,
		},
		{
			name: "ordering after something that is not a container in this project",
			units: map[string]string{
				"web.container": "[Unit]\nAfter=network-online.target\n[Container]\nImage=nginx\n",
			},
			wantFindings: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := runRule(t, "QD020", hostctx.Unknown{}, namedUnits(t, tt.units)...)

			if len(got) != tt.wantFindings {
				t.Fatalf("findings = %d, want %d: %+v", len(got), tt.wantFindings, got)
			}
			if tt.wantContains != "" && !strings.Contains(got[0].Message, tt.wantContains) {
				t.Errorf("message %q does not mention %q", got[0].Message, tt.wantContains)
			}
		})
	}
}

func TestQD020AdaptsToWhetherAHealthcheckExists(t *testing.T) {
	// Notify=healthy requires a healthcheck. Recommending it to someone who
	// has none, without saying so, produces a unit that never starts.
	withCheck := namedUnits(t, map[string]string{
		"web.container": "[Unit]\nAfter=db.service\n[Container]\nImage=nginx\n",
		"db.container":  "[Container]\nImage=postgres\nHealthCmd=pg_isready\n",
	})
	withoutCheck := namedUnits(t, map[string]string{
		"web.container": "[Unit]\nAfter=db.service\n[Container]\nImage=nginx\n",
		"db.container":  "[Container]\nImage=postgres\n",
	})

	got := runRule(t, "QD020", hostctx.Unknown{}, withCheck...)
	if len(got) != 1 {
		t.Fatalf("findings = %d, want 1", len(got))
	}
	if !strings.Contains(got[0].Remediation, "one-line change") {
		t.Errorf("with a healthcheck present the remediation should be short:\n%s", got[0].Remediation)
	}

	got = runRule(t, "QD020", hostctx.Unknown{}, withoutCheck...)
	if len(got) != 1 {
		t.Fatalf("findings = %d, want 1", len(got))
	}
	if !strings.Contains(got[0].Remediation, "HealthCmd=") {
		t.Errorf("without a healthcheck the remediation must explain how to add one:\n%s", got[0].Remediation)
	}
}

func TestQD021(t *testing.T) {
	tests := []struct {
		name         string
		text         string
		wantFindings int
	}{
		{
			name:         "unless-stopped is silently ignored by systemd",
			text:         "[Container]\nImage=nginx\n[Service]\nRestart=unless-stopped\n",
			wantFindings: 1,
		},
		{
			name:         "always is a real policy",
			text:         "[Container]\nImage=nginx\n[Service]\nRestart=always\n",
			wantFindings: 0,
		},
		{
			name:         "on-failure is a real policy",
			text:         "[Container]\nImage=nginx\n[Service]\nRestart=on-failure\n",
			wantFindings: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := unitFromText(t, "web.container", tt.text)
			got := runRule(t, "QD021", hostctx.Unknown{}, u)

			if len(got) != tt.wantFindings {
				t.Fatalf("findings = %d, want %d: %+v", len(got), tt.wantFindings, got)
			}
		})
	}
}

func TestQD021SaysItIsIgnoredNotRejected(t *testing.T) {
	// Verified with systemd-analyze verify: systemd logs "Failed to parse
	// Restart=unless-stopped, ignoring" and carries on with no policy, which
	// is worse than a hard failure because nothing draws attention to it.
	u := unitFromText(t, "web.container",
		"[Container]\nImage=nginx\n[Service]\nRestart=unless-stopped\n")

	got := runRule(t, "QD021", hostctx.Unknown{}, u)
	if len(got) != 1 {
		t.Fatalf("findings = %d, want 1", len(got))
	}
	if !strings.Contains(got[0].Message, "ignores") {
		t.Errorf("the message should say systemd ignores it: %s", got[0].Message)
	}
	if !strings.Contains(got[0].Remediation, "Restart=always") {
		t.Errorf("remediation should name the replacement:\n%s", got[0].Remediation)
	}
}

// TestConvertedFixtureIsClean checks that our own conversion output does not
// trip the rules it exists to prevent. Anything it does trip should be a
// genuine problem in the compose file, not an artefact of conversion.
func TestGeneratedUnitsDoNotTripStructuralRules(t *testing.T) {
	// The converter emits a shared network and [Install] sections, so QD030
	// and QD022 must be silent on its output.
	units := namedUnits(t, map[string]string{
		"stack.network": "[Network]\nNetworkName=stack\n[Install]\nWantedBy=default.target\n",
		"web.container": "[Container]\nImage=docker.io/library/nginx:1.27\n" +
			"Network=stack.network\n[Install]\nWantedBy=default.target\n",
		"db.container": "[Container]\nImage=docker.io/library/postgres:16\n" +
			"Network=stack.network\n[Install]\nWantedBy=default.target\n",
	})

	for _, ruleID := range []string{"QD030", "QD022", "QD021", "QD023"} {
		if got := runRule(t, ruleID, hostctx.Unknown{}, units...); len(got) != 0 {
			t.Errorf("%s fired on well-formed converted units: %+v", ruleID, got)
		}
	}
}
