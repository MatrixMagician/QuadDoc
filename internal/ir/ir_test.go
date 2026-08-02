package ir

import (
	"reflect"
	"testing"
)

func TestParseMount(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		want    Mount
		wantObj string // expected VolumeObjectName, when it differs from Source
	}{
		{
			name:  "bind with destination only",
			value: "/srv/site:/usr/share/nginx/html",
			want: Mount{
				Source: "/srv/site", Destination: "/usr/share/nginx/html",
				Type: MountBind,
			},
		},
		{
			name:  "bind with options",
			value: "/srv/site:/data:ro,Z",
			want: Mount{
				Source: "/srv/site", Destination: "/data",
				Options: []string{"ro", "Z"}, Type: MountBind,
			},
		},
		{
			name:  "anonymous volume",
			value: "/data",
			want:  Mount{Destination: "/data", Type: MountAnonymous},
		},
		{
			name:  "named volume",
			value: "pgdata:/var/lib/postgresql/data",
			want: Mount{
				Source: "pgdata", Destination: "/var/lib/postgresql/data",
				Type: MountNamed,
			},
		},
		{
			name:  "quadlet volume unit reference",
			value: "pg.volume:/var/lib/postgresql/data",
			want: Mount{
				Source: "pg.volume", Destination: "/var/lib/postgresql/data",
				Type: MountNamed, UnitRef: "pg",
			},
			// Verified against Podman 5.8.4: pg.volume becomes systemd-pg.
			wantObj: "systemd-pg",
		},
		{
			name:  "relative source is a bind, resolved against the unit file",
			value: "./data:/data:Z",
			want: Mount{
				Source: "./data", Destination: "/data",
				Options: []string{"Z"}, Type: MountBind,
			},
		},
		{
			name:  "systemd specifier source is a bind",
			value: "%h/data:/data",
			want:  Mount{Source: "%h/data", Destination: "/data", Type: MountBind},
		},
		{
			name:  "destination containing a colon",
			value: "/src:/weird:dest:ro",
			want: Mount{
				Source: "/src", Destination: "/weird:dest",
				Options: []string{"ro"}, Type: MountBind,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseMount(tt.value, 1)
			tt.want.Line, tt.want.Raw = 1, tt.value

			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseMount(%q) =\n  %+v\nwant\n  %+v", tt.value, got, tt.want)
			}
			if tt.wantObj != "" {
				if obj := got.VolumeObjectName(); obj != tt.wantObj {
					t.Errorf("VolumeObjectName() = %q, want %q", obj, tt.wantObj)
				}
			}
		})
	}
}

func TestMountOptionCaseIsSignificant(t *testing.T) {
	// `:z` and `:Z` are different instructions, shared versus private
	// relabelling, and conflating them is the bug QD002 exists to catch.
	private := ParseMount("/srv:/data:Z", 1)
	shared := ParseMount("/srv:/data:z", 1)

	if !private.HasOption("Z") || private.HasOption("z") {
		t.Error("`:Z` must match Z and not z")
	}
	if !shared.HasOption("z") || shared.HasOption("Z") {
		t.Error("`:z` must match z and not Z")
	}
	if !private.HasSELinuxLabel() || !shared.HasSELinuxLabel() {
		t.Error("both forms are SELinux labels")
	}
	if ParseMount("/srv:/data:ro", 1).HasSELinuxLabel() {
		t.Error("`:ro` is not an SELinux label")
	}
}

func TestParsePort(t *testing.T) {
	tests := []struct {
		value         string
		wantHostIP    string
		wantHost      int
		wantContainer int
		wantProto     string
		wantOK        bool
	}{
		{value: "8080:80", wantHost: 8080, wantContainer: 80, wantProto: "tcp", wantOK: true},
		{value: "80", wantContainer: 80, wantProto: "tcp", wantOK: true},
		{value: "127.0.0.1:8080:80", wantHostIP: "127.0.0.1", wantHost: 8080, wantContainer: 80, wantProto: "tcp", wantOK: true},
		{value: "53:53/udp", wantHost: 53, wantContainer: 53, wantProto: "udp", wantOK: true},
		{value: "443:443", wantHost: 443, wantContainer: 443, wantProto: "tcp", wantOK: true},
		{value: "not-a-port", wantOK: false},
	}

	for _, tt := range tests {
		t.Run(tt.value, func(t *testing.T) {
			got, ok := ParsePort(tt.value, 1)
			if ok != tt.wantOK {
				t.Fatalf("ParsePort(%q) ok = %v, want %v", tt.value, ok, tt.wantOK)
			}
			if !ok {
				return
			}
			if got.HostIP != tt.wantHostIP || got.HostPort != tt.wantHost ||
				got.ContainerPort != tt.wantContainer || got.Protocol != tt.wantProto {
				t.Errorf("ParsePort(%q) = %+v, want ip=%q host=%d container=%d proto=%q",
					tt.value, got, tt.wantHostIP, tt.wantHost, tt.wantContainer, tt.wantProto)
			}
		})
	}
}

func TestBindSourceUsageCountsUnitsNotMounts(t *testing.T) {
	// A unit mounting one source at two destinations has not made it shared,
	// so the count must be per unit. QD002 turns on this number.
	p := &Project{Units: []*Unit{
		{Name: "a", Kind: KindContainer, Mounts: []Mount{
			{Source: "/srv/shared", Type: MountBind},
			{Source: "/srv/shared", Type: MountBind},
			{Source: "/srv/only-a", Type: MountBind},
		}},
		{Name: "b", Kind: KindContainer, Mounts: []Mount{
			{Source: "/srv/shared", Type: MountBind},
			{Source: "pgdata", Type: MountNamed},
		}},
	}}

	usage := p.BindSourceUsage()
	if got := usage["/srv/shared"]; got != 2 {
		t.Errorf("shared source used by %d units, want 2", got)
	}
	if got := usage["/srv/only-a"]; got != 1 {
		t.Errorf("private source used by %d units, want 1", got)
	}
	if _, ok := usage["pgdata"]; ok {
		t.Error("named volumes must not appear in the bind-source map")
	}
}

func TestKindFromPath(t *testing.T) {
	tests := map[string]UnitKind{
		"web.container":      KindContainer,
		"pg.volume":          KindVolume,
		"app.network":        KindNetwork,
		"stack.pod":          KindPod,
		"README.md":          KindUnknown,
		"compose.yaml":       KindUnknown,
		"/a/b/web.container": KindContainer,
		"noextension":        KindUnknown,
	}
	for path, want := range tests {
		if got := KindFromPath(path); got != want {
			t.Errorf("KindFromPath(%q) = %q, want %q", path, got, want)
		}
	}
}

func TestParseEnvKeepsQuotedValuesTogether(t *testing.T) {
	got := parseEnv(`A=1 B="two words" C=3`, 7)
	want := []EnvVar{
		{Name: "A", Value: "1", Line: 7},
		{Name: "B", Value: "two words", Line: 7},
		{Name: "C", Value: "3", Line: 7},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseEnv =\n  %+v\nwant\n  %+v", got, want)
	}
}
