package rules

import (
	"strings"
	"testing"

	"github.com/MatrixMagician/quaddoc/internal/hostctx"
	"github.com/MatrixMagician/quaddoc/internal/ir"
)

// enforcing is a host where SELinux is on, matching the reference platform.
var enforcing = hostctx.Static{SELinuxMode: hostctx.SELinuxEnforcing}

func TestQD001(t *testing.T) {
	tests := []struct {
		name         string
		text         string
		wantFindings int
		wantOption   string
	}{
		{
			name:         "an unlabelled bind mount is an error",
			text:         "[Container]\nImage=nginx\nVolume=/srv/site:/usr/share/nginx/html\n",
			wantFindings: 1,
			wantOption:   ":Z", // used by one unit, so private
		},
		{
			name:         "a labelled bind mount is fine",
			text:         "[Container]\nImage=nginx\nVolume=/srv/site:/usr/share/nginx/html:Z\n",
			wantFindings: 0,
		},
		{
			name:         "a shared label is also fine",
			text:         "[Container]\nImage=nginx\nVolume=/srv/site:/usr/share/nginx/html:z\n",
			wantFindings: 0,
		},
		{
			name:         "a named volume needs no relabelling",
			text:         "[Container]\nImage=postgres\nVolume=pgdata.volume:/var/lib/postgresql/data\n",
			wantFindings: 0,
		},
		{
			name:         "an anonymous volume needs no relabelling",
			text:         "[Container]\nImage=nginx\nVolume=/data\n",
			wantFindings: 0,
		},
		{
			// SELinux denies the read as well as the write, so read-only
			// mounts are not exempt.
			name:         "a read-only bind mount still needs a label",
			text:         "[Container]\nImage=nginx\nVolume=/srv/site:/data:ro\n",
			wantFindings: 1,
		},
		{
			// QD004's territory: recommending :Z here would be harmful.
			name:         "a system path is left to QD004",
			text:         "[Container]\nImage=nginx\nVolume=/home:/data\n",
			wantFindings: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := unitFromText(t, "web.container", tt.text)
			got := runRule(t, "QD001", enforcing, u)

			if len(got) != tt.wantFindings {
				t.Fatalf("findings = %d, want %d: %+v", len(got), tt.wantFindings, got)
			}
			if tt.wantOption != "" && !strings.Contains(got[0].Remediation, tt.wantOption) {
				t.Errorf("remediation should suggest %s:\n%s", tt.wantOption, got[0].Remediation)
			}
		})
	}
}

func TestQD001SuggestsSharedLabelForSharedSource(t *testing.T) {
	// The whole point of computing sharing project-wide: the right option
	// depends on units other than the one being examined.
	web := unitFromText(t, "web.container", "[Container]\nImage=nginx\nVolume=/srv/certs:/certs\n")
	db := unitFromText(t, "db.container", "[Container]\nImage=postgres\nVolume=/srv/certs:/certs\n")

	got := runRule(t, "QD001", enforcing, web, db)
	if len(got) != 2 {
		t.Fatalf("findings = %d, want 2 (one per unit)", len(got))
	}
	for _, f := range got {
		// The suggested Volume= line is what the user pastes, so that is what
		// must carry the shared label. The prose around it legitimately
		// mentions :Z while explaining why not to use it here.
		if !strings.Contains(f.Remediation, "Volume=/srv/certs:/certs:z") {
			t.Errorf("a shared source should be given :z:\n%s", f.Remediation)
		}
		if strings.Contains(f.Remediation, "Volume=/srv/certs:/certs:Z") {
			t.Errorf("a shared source must not be given the private label:\n%s", f.Remediation)
		}
	}
}

// TestQD001AndQD002AreMutuallyExclusive is the regression test for finding F3.
//
// Both rules reason about whether a source is shared. If they derived that
// independently they could both fire for one mount, or worse, QD001's fix could
// write a :Z that QD002 then errors on. Sharing the usage map makes them
// exclusive by construction; this test keeps it that way.
func TestQD001AndQD002AreMutuallyExclusive(t *testing.T) {
	cases := []struct {
		name  string
		units []string
	}{
		{
			name: "shared source with no label",
			units: []string{
				"[Container]\nImage=a\nVolume=/srv/shared:/data\n",
				"[Container]\nImage=b\nVolume=/srv/shared:/data\n",
			},
		},
		{
			name: "shared source with the private label",
			units: []string{
				"[Container]\nImage=a\nVolume=/srv/shared:/data:Z\n",
				"[Container]\nImage=b\nVolume=/srv/shared:/data:Z\n",
			},
		},
		{
			name: "shared source with the shared label",
			units: []string{
				"[Container]\nImage=a\nVolume=/srv/shared:/data:z\n",
				"[Container]\nImage=b\nVolume=/srv/shared:/data:z\n",
			},
		},
		{
			name: "one unit labelled, one not",
			units: []string{
				"[Container]\nImage=a\nVolume=/srv/shared:/data:Z\n",
				"[Container]\nImage=b\nVolume=/srv/shared:/data\n",
			},
		},
		{
			name:  "private source with no label",
			units: []string{"[Container]\nImage=a\nVolume=/srv/only:/data\n"},
		},
		{
			name:  "private source with the private label",
			units: []string{"[Container]\nImage=a\nVolume=/srv/only:/data:Z\n"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			units := buildUnits(t, tc.units)

			qd001 := runRule(t, "QD001", enforcing, units...)
			qd002 := runRule(t, "QD002", enforcing, units...)

			// Index findings by unit and line so any overlap is detectable.
			seen := map[string]string{}
			for _, f := range qd001 {
				seen[key(f)] = "QD001"
			}
			for _, f := range qd002 {
				if other, clash := seen[key(f)]; clash {
					t.Errorf("both %s and QD002 fired for %s: this is the F3 contradiction",
						other, key(f))
				}
			}
		})
	}
}

func TestQD002(t *testing.T) {
	tests := []struct {
		name         string
		units        []string
		wantFindings int
	}{
		{
			name: "private label on a shared source is an error, once per unit",
			units: []string{
				"[Container]\nImage=a\nVolume=/srv/shared:/data:Z\n",
				"[Container]\nImage=b\nVolume=/srv/shared:/data:Z\n",
			},
			wantFindings: 2,
		},
		{
			name:         "private label on a private source is correct",
			units:        []string{"[Container]\nImage=a\nVolume=/srv/only:/data:Z\n"},
			wantFindings: 0,
		},
		{
			name: "shared label on a shared source is correct",
			units: []string{
				"[Container]\nImage=a\nVolume=/srv/shared:/data:z\n",
				"[Container]\nImage=b\nVolume=/srv/shared:/data:z\n",
			},
			wantFindings: 0,
		},
		{
			name: "the same source twice in one unit is not shared",
			units: []string{
				"[Container]\nImage=a\nVolume=/srv/only:/data:Z\nVolume=/srv/only:/other:Z\n",
			},
			wantFindings: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := runRule(t, "QD002", enforcing, buildUnits(t, tt.units)...)
			if len(got) != tt.wantFindings {
				t.Fatalf("findings = %d, want %d: %+v", len(got), tt.wantFindings, got)
			}
		})
	}
}

func TestQD003NeedsHostContext(t *testing.T) {
	// The filesystem a path lives on cannot be known from the unit alone, so
	// the rule must stay silent rather than guess.
	u := unitFromText(t, "web.container", "[Container]\nImage=nginx\nVolume=/mnt/share:/data:Z\n")

	if got := runRule(t, "QD003", hostctx.Unknown{}, u); len(got) != 0 {
		t.Errorf("QD003 fired without host context: %+v", got)
	}
}

func TestQD003(t *testing.T) {
	tests := []struct {
		name         string
		fsType       string
		options      string
		wantFindings int
		wantContains string
	}{
		{name: "nfs cannot hold per-file labels", fsType: "nfs4", wantFindings: 1, wantContains: "nfs4"},
		{name: "cifs cannot hold per-file labels", fsType: "cifs", wantFindings: 1},
		{name: "fuse cannot hold per-file labels", fsType: "fuse.sshfs", wantFindings: 1},
		{name: "vfat has no extended attributes", fsType: "vfat", wantFindings: 1},
		{name: "ext4 is fine", fsType: "ext4", wantFindings: 0},
		{name: "btrfs is fine", fsType: "btrfs", wantFindings: 0},
		{
			name:   "a context= mount makes relabelling a no-op",
			fsType: "ext4", options: "rw,context=system_u:object_r:container_file_t:s0",
			wantFindings: 1, wantContains: "context=",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host := hostctx.Static{
				SELinuxMode: hostctx.SELinuxEnforcing,
				Mounts: []hostctx.Mount{
					{MountPoint: "/", FSType: "btrfs"},
					{MountPoint: "/mnt/share", FSType: tt.fsType, Options: tt.options},
				},
			}
			u := unitFromText(t, "web.container",
				"[Container]\nImage=nginx\nVolume=/mnt/share/data:/data:Z\n")

			got := runRule(t, "QD003", host, u)
			if len(got) != tt.wantFindings {
				t.Fatalf("findings = %d, want %d: %+v", len(got), tt.wantFindings, got)
			}
			if tt.wantContains != "" && !strings.Contains(got[0].Message, tt.wantContains) {
				t.Errorf("message %q does not mention %q", got[0].Message, tt.wantContains)
			}
		})
	}
}

func TestQD003UsesTheLongestMatchingMount(t *testing.T) {
	// A shorter mount point like `/` must not shadow the specific filesystem
	// the path is actually on.
	host := hostctx.Static{
		SELinuxMode: hostctx.SELinuxEnforcing,
		Mounts: []hostctx.Mount{
			{MountPoint: "/", FSType: "btrfs"},
			{MountPoint: "/mnt", FSType: "ext4"},
			{MountPoint: "/mnt/nfs", FSType: "nfs4"},
		},
	}
	u := unitFromText(t, "web.container",
		"[Container]\nImage=nginx\nVolume=/mnt/nfs/data:/data:Z\n")

	got := runRule(t, "QD003", host, u)
	if len(got) != 1 {
		t.Fatalf("findings = %d, want 1: %+v", len(got), got)
	}
	if !strings.Contains(got[0].Message, "nfs4") {
		t.Errorf("the longest matching mount should have won: %s", got[0].Message)
	}
}

func TestQD004(t *testing.T) {
	tests := []struct {
		name         string
		source       string
		option       string
		wantFindings int
	}{
		{name: "relabelling /home is an error", source: "/home", option: ":Z", wantFindings: 1},
		{name: "relabelling /var/lib is an error", source: "/var/lib", option: ":z", wantFindings: 1},
		{name: "relabelling /etc is an error", source: "/etc", option: ":Z", wantFindings: 1},
		{name: "relabelling / is an error", source: "/", option: ":Z", wantFindings: 1},
		{name: "trailing slash still matches", source: "/home/", option: ":Z", wantFindings: 1},
		{
			// The rule must not be so broad it becomes useless: a
			// subdirectory is exactly what users should be mounting.
			name:   "a subdirectory of a system path is fine",
			source: "/var/lib/myapp", option: ":Z", wantFindings: 0,
		},
		{
			name:   "a user's own directory is fine",
			source: "/home/alice/project", option: ":Z", wantFindings: 0,
		},
		{
			name:   "a system path without relabelling is not this rule's business",
			source: "/home", option: "", wantFindings: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := unitFromText(t, "web.container",
				"[Container]\nImage=nginx\nVolume="+tt.source+":/data"+tt.option+"\n")

			got := runRule(t, "QD004", enforcing, u)
			if len(got) != tt.wantFindings {
				t.Fatalf("findings = %d, want %d: %+v", len(got), tt.wantFindings, got)
			}
			if tt.wantFindings > 0 && !strings.Contains(got[0].Remediation, "restorecon") {
				t.Errorf("remediation should explain how to repair the damage:\n%s", got[0].Remediation)
			}
		})
	}
}

func TestQD004FiresRegardlessOfSELinuxMode(t *testing.T) {
	// The damage happens at relabel time. A machine that is permissive today
	// may be enforcing tomorrow with its labels already rewritten.
	u := unitFromText(t, "web.container", "[Container]\nImage=nginx\nVolume=/home:/data:Z\n")

	for _, mode := range []hostctx.SELinuxMode{
		hostctx.SELinuxEnforcing, hostctx.SELinuxPermissive,
		hostctx.SELinuxDisabled, hostctx.SELinuxUnknown,
	} {
		t.Run(mode.String(), func(t *testing.T) {
			got := runRule(t, "QD004", hostctx.Static{SELinuxMode: mode}, u)
			if len(got) != 1 {
				t.Errorf("findings = %d under %s, want 1", len(got), mode)
			}
		})
	}
}

// TestSELinuxDowngradeMatrix is the fixture matrix the spec calls for:
// enforcing, permissive, and absent, with the severities each produces.
func TestSELinuxDowngradeMatrix(t *testing.T) {
	unlabelled := "[Container]\nImage=nginx\nVolume=/srv/site:/data\n"

	tests := []struct {
		mode           hostctx.SELinuxMode
		wantFindings   int
		wantSeverity   Severity
		wantConfidence Confidence
	}{
		{
			mode: hostctx.SELinuxEnforcing, wantFindings: 1,
			wantSeverity: Error, wantConfidence: Confirmed,
		},
		{
			// Still wrong, just not enforced today. Turning enforcing back on
			// would break the container, so it is worth saying.
			mode: hostctx.SELinuxPermissive, wantFindings: 1,
			wantSeverity: Note, wantConfidence: Confirmed,
		},
		{
			// Meaningless on a kernel without SELinux.
			mode: hostctx.SELinuxDisabled, wantFindings: 0,
		},
		{
			// No host context: report at the default severity, worded as a
			// possibility.
			mode: hostctx.SELinuxUnknown, wantFindings: 1,
			wantSeverity: Error, wantConfidence: Possible,
		},
	}

	for _, tt := range tests {
		t.Run(tt.mode.String(), func(t *testing.T) {
			u := unitFromText(t, "web.container", unlabelled)
			got := runRule(t, "QD001", hostctx.Static{SELinuxMode: tt.mode}, u)

			if len(got) != tt.wantFindings {
				t.Fatalf("findings = %d, want %d: %+v", len(got), tt.wantFindings, got)
			}
			if tt.wantFindings == 0 {
				return
			}
			if got[0].Severity != tt.wantSeverity {
				t.Errorf("severity = %v, want %v", got[0].Severity, tt.wantSeverity)
			}
			if got[0].Confidence != tt.wantConfidence {
				t.Errorf("confidence = %v, want %v", got[0].Confidence, tt.wantConfidence)
			}
		})
	}
}

func TestSELinuxFindingsAreWordedForTheirConfidence(t *testing.T) {
	// A finding derived from the units alone must not assert a fact about the
	// host it never checked.
	u := unitFromText(t, "web.container", "[Container]\nImage=nginx\nVolume=/srv/site:/data\n")

	possible := runRule(t, "QD001", hostctx.Unknown{}, u)
	confirmed := runRule(t, "QD001", enforcing, u)

	if len(possible) != 1 || len(confirmed) != 1 {
		t.Fatal("expected one finding in each mode")
	}
	if possible[0].Message == confirmed[0].Message {
		t.Error("a possible finding should be worded differently from a confirmed one")
	}
	if !strings.Contains(confirmed[0].Message, "is enforcing") {
		t.Errorf("a confirmed finding should say so: %s", confirmed[0].Message)
	}
	if !strings.Contains(possible[0].Message, "would") {
		t.Errorf("a possible finding should be hedged: %s", possible[0].Message)
	}
}

func key(f Finding) string {
	return f.Unit + ":" + itoa(f.Line)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}

// TestHostDowngradeResistsBeingRaisedByConfig covers the interaction between
// the two things that can change a severity.
//
// A project may raise a rule it cares about. It may not raise a finding the
// host has established does not apply here: under a permissive kernel the
// label is still wrong, but it is not being enforced today, and reporting that
// as an error would be asserting something untrue about the machine. See
// ADR-0004.
func TestHostDowngradeResistsBeingRaisedByConfig(t *testing.T) {
	unit := unitFromText(t, "web.container",
		"[Container]\nImage=nginx\nVolume=/srv/site:/data\n")

	tests := []struct {
		name     string
		mode     hostctx.SELinuxMode
		override Severity
		want     Severity
	}{
		{
			name: "enforcing honours a raise",
			mode: hostctx.SELinuxEnforcing, override: Error, want: Error,
		},
		{
			name: "enforcing honours a lowering",
			mode: hostctx.SELinuxEnforcing, override: Note, want: Note,
		},
		{
			// The host downgraded this to a note. Configuration asking for an
			// error does not make SELinux enforcing.
			name: "permissive resists a raise",
			mode: hostctx.SELinuxPermissive, override: Error, want: Note,
		},
		{
			// Lowering further is still the project's business.
			name: "permissive accepts a further lowering",
			mode: hostctx.SELinuxPermissive, override: Note, want: Note,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engine := &Engine{
				Host:   hostctx.Static{SELinuxMode: tt.mode},
				Config: Config{SeverityOverride: map[string]Severity{"QD001": tt.override}},
			}
			project := &ir.Project{Units: []*ir.Unit{unit}}

			var found bool
			for _, f := range engine.Run(project) {
				if f.RuleID != "QD001" {
					continue
				}
				found = true
				if f.Severity != tt.want {
					t.Errorf("severity = %v, want %v", f.Severity, tt.want)
				}
			}
			if !found {
				t.Fatal("QD001 did not fire")
			}
		})
	}
}
