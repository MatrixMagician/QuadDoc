package ir

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/MatrixMagician/quaddoc/internal/parse/quadlet"
)

// writeUnits creates a directory of unit files.
func writeUnits(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatalf("writing %s: %v", name, err)
		}
	}
	return dir
}

func TestLoadProject(t *testing.T) {
	dir := writeUnits(t, map[string]string{
		"web.container": "[Container]\nImage=nginx\n",
		"db.container":  "[Container]\nImage=postgres\n",
		"data.volume":   "[Volume]\n",
		"app.network":   "[Network]\n",
		// Neither of these is a Quadlet unit, and pointing quaddoc at a
		// directory that also holds them should be harmless.
		"README.md":    "# not a unit\n",
		"compose.yaml": "services: {}\n",
	})

	p, err := LoadProject(dir)
	if err != nil {
		t.Fatalf("LoadProject: %v", err)
	}

	if len(p.Units) != 4 {
		t.Fatalf("loaded %d units, want 4: %v", len(p.Units), unitNames(p))
	}
	if p.Root != dir {
		t.Errorf("root = %q, want %q", p.Root, dir)
	}
}

func TestLoadProjectSortsDeterministically(t *testing.T) {
	// Output must not depend on the order the filesystem happened to return.
	dir := writeUnits(t, map[string]string{
		"z.container": "[Container]\nImage=z\n",
		"a.container": "[Container]\nImage=a\n",
		"m.container": "[Container]\nImage=m\n",
	})

	var first []string
	for i := 0; i < 10; i++ {
		p, err := LoadProject(dir)
		if err != nil {
			t.Fatalf("LoadProject: %v", err)
		}
		names := unitNames(p)
		if i == 0 {
			first = names
			continue
		}
		if strings.Join(names, ",") != strings.Join(first, ",") {
			t.Fatalf("order varies between loads: %v then %v", first, names)
		}
	}
}

func TestLoadProjectAcceptsASingleFile(t *testing.T) {
	// A file named explicitly is loaded whatever its extension: the user asked
	// for it by name, so refusing would be unhelpful.
	dir := writeUnits(t, map[string]string{"web.container": "[Container]\nImage=nginx\n"})

	p, err := LoadProject(filepath.Join(dir, "web.container"))
	if err != nil {
		t.Fatalf("LoadProject: %v", err)
	}
	if len(p.Units) != 1 {
		t.Fatalf("loaded %d units, want 1", len(p.Units))
	}
	if p.Root != dir {
		t.Errorf("root = %q, want the file's directory %q", p.Root, dir)
	}
}

func TestLoadProjectReportsAMissingPath(t *testing.T) {
	if _, err := LoadProject(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Error("a missing path should be an error")
	}
}

func TestFromParsedPopulatesTheModel(t *testing.T) {
	text := `[Unit]
Description=Web front end

[Container]
Image=docker.io/library/nginx:1.27
ContainerName=web
Volume=/srv/site:/data:Z
Volume=pg.volume:/var/lib/pg
PublishPort=8080:80
PublishPort=8443:443
Network=app.network
Environment=A=1 B=two
Environment=C=3
User=1000
Group=1000
GroupAdd=keep-groups
UserNS=keep-id
AutoUpdate=registry
Notify=healthy
HealthCmd=curl -f http://localhost/
Pod=stack.pod

[Service]
Restart=always

[Install]
WantedBy=default.target
Alias=web.service
`
	f, err := quadlet.Parse("web.container", strings.NewReader(text))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	u := FromParsed(f)

	if u.Name != "web" || u.Kind != KindContainer {
		t.Errorf("name/kind = %q/%q, want web/container", u.Name, u.Kind)
	}
	if u.Image != "docker.io/library/nginx:1.27" {
		t.Errorf("image = %q", u.Image)
	}
	if len(u.Mounts) != 2 {
		t.Errorf("mounts = %d, want 2", len(u.Mounts))
	}
	if len(u.Ports) != 2 {
		t.Errorf("ports = %d, want 2", len(u.Ports))
	}
	if len(u.Networks) != 1 || u.Networks[0] != "app.network" {
		t.Errorf("networks = %v", u.Networks)
	}
	// Two Environment= lines, the first carrying two assignments.
	if len(u.Environment) != 3 {
		t.Errorf("environment = %d entries, want 3: %+v", len(u.Environment), u.Environment)
	}
	if u.User != "1000" || u.Group != "1000" {
		t.Errorf("user/group = %q/%q", u.User, u.Group)
	}
	if len(u.GroupAdd) != 1 || u.GroupAdd[0] != "keep-groups" {
		t.Errorf("groupAdd = %v", u.GroupAdd)
	}
	if u.UserNS != "keep-id" || u.AutoUpdate != "registry" || u.Notify != "healthy" {
		t.Errorf("userns/autoupdate/notify = %q/%q/%q", u.UserNS, u.AutoUpdate, u.Notify)
	}
	if !u.HasHealthCmd {
		t.Error("HasHealthCmd should be true")
	}
	if u.Pod != "stack.pod" {
		t.Errorf("pod = %q", u.Pod)
	}
	// Restart lives in [Service]: it is a systemd key, not a Quadlet one.
	if u.Restart != "always" {
		t.Errorf("restart = %q, want always", u.Restart)
	}
	if !u.HasInstall || len(u.InstallKeys) != 2 {
		t.Errorf("install = %v with %d keys, want true with 2", u.HasInstall, len(u.InstallKeys))
	}
	// Entries carries every assignment, including keys the model does not
	// otherwise capture, which is what QD042 needs.
	if len(u.Entries) < 20 {
		t.Errorf("entries = %d, want every assignment in the file", len(u.Entries))
	}
}

func TestEmptyAssignmentResetsListKeys(t *testing.T) {
	// systemd.syntax(7): an empty assignment resets a list. Verified against
	// Podman 5.8.4: this unit generates `-v /b:/b` and no --network,
	// --publish, --env or --group-add.
	f, err := quadlet.Parse("web.container", strings.NewReader(`[Container]
Image=nginx
Volume=/a:/a
Volume=
Volume=/b:/b
Network=app.network
Network=
PublishPort=80:80
PublishPort=
Environment=A=1
Environment=
GroupAdd=video
GroupAdd=
`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	u := FromParsed(f)

	if len(u.Mounts) != 1 || u.Mounts[0].Source != "/b" {
		t.Errorf("mounts = %+v, want only /b", u.Mounts)
	}
	if len(u.Networks) != 0 || len(u.Ports) != 0 || len(u.Environment) != 0 || len(u.GroupAdd) != 0 {
		t.Errorf("networks/ports/environment/groupAdd = %v/%v/%v/%v, want all empty",
			u.Networks, u.Ports, u.Environment, u.GroupAdd)
	}
}

func TestLowercaseSectionsAndKeysAreNotModelled(t *testing.T) {
	// Verified against Podman 5.8.4: the generator matches section and key
	// names exactly, so neither unit has an Image, and [service] carries no
	// Restart=.
	for _, text := range []string{
		"[container]\nimage=nginx\nvolume=/srv:/data\n[service]\nRestart=always\n[install]\nWantedBy=default.target\n",
		"[Container]\nimage=nginx\nvolume=/srv:/data\n[Service]\nrestart=always\n",
	} {
		f, err := quadlet.Parse("web.container", strings.NewReader(text))
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		u := FromParsed(f)
		if u.Image != "" || len(u.Mounts) != 0 || u.Restart != "" || u.HasInstall {
			t.Errorf("%q loaded image=%q mounts=%v restart=%q install=%v, want none",
				text, u.Image, u.Mounts, u.Restart, u.HasInstall)
		}
	}
}

func TestHealthCmdNoneMeansNoHealthcheck(t *testing.T) {
	// podman-systemd.unit(5): "A value of none disables existing healthchecks."
	f, err := quadlet.Parse("web.container",
		strings.NewReader("[Container]\nImage=nginx\nHealthCmd=none\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if FromParsed(f).HasHealthCmd {
		t.Error("HealthCmd=none should not count as having a healthcheck")
	}
}

func TestKeyLine(t *testing.T) {
	// Findings cite lines, so the loader must record where each key was.
	f, err := quadlet.Parse("web.container", strings.NewReader(
		"[Container]\n# a comment\nImage=nginx\n\nUser=1000\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	u := FromParsed(f)

	if got := u.KeyLine("Image"); got != 3 {
		t.Errorf("KeyLine(Image) = %d, want 3", got)
	}
	if got := u.KeyLine("User"); got != 5 {
		t.Errorf("KeyLine(User) = %d, want 5", got)
	}
	// Case-sensitive, as the generator is.
	if got := u.KeyLine("image"); got != 0 {
		t.Errorf("KeyLine(image) = %d, want 0", got)
	}
	// A key that was never set has no line, rather than line zero being
	// mistaken for line one.
	if got := u.KeyLine("Notify"); got != 0 {
		t.Errorf("KeyLine of an absent key = %d, want 0", got)
	}
}

func TestKeyLineOnAUnitWithNoSource(t *testing.T) {
	// Generated units carry no source file, so this must not panic.
	u := &Unit{Name: "generated", Kind: KindContainer}
	if got := u.KeyLine("Image"); got != 0 {
		t.Errorf("KeyLine = %d, want 0", got)
	}
}

func TestSectionForEachKind(t *testing.T) {
	tests := map[UnitKind]string{
		KindContainer: "Container",
		KindVolume:    "Volume",
		KindNetwork:   "Network",
		KindPod:       "Pod",
		KindUnknown:   "",
	}
	for kind, want := range tests {
		if got := kind.Section(); got != want {
			t.Errorf("%q.Section() = %q, want %q", kind, got, want)
		}
	}
}

func TestContainers(t *testing.T) {
	p := &Project{Units: []*Unit{
		{Name: "web", Kind: KindContainer},
		{Name: "data", Kind: KindVolume},
		{Name: "db", Kind: KindContainer},
		{Name: "app", Kind: KindNetwork},
	}}

	got := p.Containers()
	if len(got) != 2 {
		t.Fatalf("containers = %d, want 2", len(got))
	}
	for _, u := range got {
		if u.Kind != KindContainer {
			t.Errorf("%s is a %s, not a container", u.Name, u.Kind)
		}
	}
}

func TestUnitByName(t *testing.T) {
	p := &Project{Units: []*Unit{
		{Name: "app", Kind: KindContainer},
		{Name: "app", Kind: KindNetwork},
	}}

	// The same name may exist as two kinds, so both must be selectable.
	if u, ok := p.UnitByName("app", KindNetwork); !ok || u.Kind != KindNetwork {
		t.Error("did not find the network unit named app")
	}
	if u, ok := p.UnitByName("app", KindContainer); !ok || u.Kind != KindContainer {
		t.Error("did not find the container unit named app")
	}
	if _, ok := p.UnitByName("nope", KindContainer); ok {
		t.Error("found a unit that does not exist")
	}
}

func TestNamedVolumeUsers(t *testing.T) {
	// QD012 needs to know which units share a volume, counted per unit rather
	// than per mount.
	p := &Project{Units: []*Unit{
		{Name: "a", Kind: KindContainer, Mounts: []Mount{
			{Source: "shared", Type: MountNamed},
			{Source: "shared", Type: MountNamed}, // same unit twice
			{Source: "onlya", Type: MountNamed},
		}},
		{Name: "b", Kind: KindContainer, Mounts: []Mount{
			{Source: "shared", Type: MountNamed},
			{Source: "/srv/bind", Type: MountBind},
		}},
	}}

	users := p.NamedVolumeUsers()
	if got := len(users["shared"]); got != 2 {
		t.Errorf("shared volume used by %d units, want 2", got)
	}
	if got := len(users["onlya"]); got != 1 {
		t.Errorf("private volume used by %d units, want 1", got)
	}
	if _, present := users["/srv/bind"]; present {
		t.Error("bind mounts must not appear in the named-volume map")
	}
}

func TestSortIsStable(t *testing.T) {
	p := &Project{Units: []*Unit{
		{Path: "z.container"}, {Path: "a.container"}, {Path: "m.container"},
	}}
	p.Sort()

	want := []string{"a.container", "m.container", "z.container"}
	for i, u := range p.Units {
		if u.Path != want[i] {
			t.Errorf("unit %d = %q, want %q", i, u.Path, want[i])
		}
	}
}

func TestVolumeObjectNameAppliesTheSystemdPrefix(t *testing.T) {
	// Verified against Podman 5.8.4: pg.volume creates a volume named
	// systemd-pg. QD032 compares against real object names, so this matters.
	m := ParseMount("pg.volume:/data", 1)
	if got := m.VolumeObjectName(); got != "systemd-pg" {
		t.Errorf("VolumeObjectName = %q, want systemd-pg", got)
	}

	// A plain named volume is used as written.
	m = ParseMount("pgdata:/data", 1)
	if got := m.VolumeObjectName(); got != "pgdata" {
		t.Errorf("VolumeObjectName = %q, want pgdata", got)
	}
}

func TestObjectNameHonoursVolumeNameAndNetworkName(t *testing.T) {
	// Verified against Podman 5.8.4: VolumeName= and NetworkName= replace the
	// systemd- default, so `data.volume` with VolumeName=pg_data creates pg_data.
	p, err := LoadProject(writeUnits(t, map[string]string{
		"data.volume":   "[Volume]\nVolumeName=pg_data\n",
		"pg.volume":     "[Volume]\n",
		"front.network": "[Network]\nNetworkName=public_net\n",
		"back.network":  "[Network]\n",
	}))
	if err != nil {
		t.Fatalf("loading: %v", err)
	}

	for _, tt := range []struct {
		name string
		kind UnitKind
		want string
	}{
		{"data", KindVolume, "pg_data"},
		{"pg", KindVolume, "systemd-pg"},
		{"front", KindNetwork, "public_net"},
		{"back", KindNetwork, "systemd-back"},
	} {
		u, ok := p.UnitByName(tt.name, tt.kind)
		if !ok {
			t.Fatalf("no %s.%s loaded", tt.name, tt.kind)
		}
		if got := u.ObjectName(); got != tt.want {
			t.Errorf("%s.%s ObjectName() = %q, want %q", tt.name, tt.kind, got, tt.want)
		}
	}
}

func TestLoadUnitReportsAMissingFile(t *testing.T) {
	if _, err := LoadUnit(filepath.Join(t.TempDir(), "nope.container")); err == nil {
		t.Error("a missing file should be an error")
	}
}

func TestFromParsedOnANonUnitExtension(t *testing.T) {
	// A file with no recognised extension has no section to read, so the
	// model stays empty rather than guessing.
	f, err := quadlet.Parse("notes.txt", strings.NewReader("[Container]\nImage=nginx\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	u := FromParsed(f)

	if u.Kind != KindUnknown {
		t.Errorf("kind = %q, want unknown", u.Kind)
	}
	if u.Image != "" {
		t.Errorf("image = %q, want empty for an unknown unit type", u.Image)
	}
}

func TestMountKeyBindEntriesAreModelled(t *testing.T) {
	// podman-run(1) --mount, and the generator's own treatment of each form,
	// verified against Podman 5.8.4 (quadlet -dryrun and podman create/inspect).
	tests := []struct {
		name  string
		value string
		want  []Mount // nil: not modelled as a bind mount
	}{
		{
			name:  "a plain bind mount",
			value: "type=bind,source=/srv/web,destination=/data",
			want:  []Mount{{Source: "/srv/web", Destination: "/data", Type: MountBind}},
		},
		{
			name:  "short keys and every normalised option",
			value: "type=bind,src=./rel,dst=/rel,relabel=private,U=true,ro",
			want:  []Mount{{Source: "./rel", Destination: "/rel", Type: MountBind, Options: []string{"Z", "U", "ro"}}},
		},
		{
			name:  "fields in any order, long synonyms",
			value: "destination=/d,type=bind,source=%h/x,readonly=TRUE,relabel=shared,chown",
			want:  []Mount{{Source: "%h/x", Destination: "/d", Type: MountBind, Options: []string{"ro", "z", "U"}}},
		},
		{
			name:  "target is a destination synonym and bare Z is accepted",
			value: "type=bind,source=/s,target=/t,Z",
			want:  []Mount{{Source: "/s", Destination: "/t", Type: MountBind, Options: []string{"Z"}}},
		},
		{
			// podman reads any boolean other than bare or "true" as false:
			// ro=1 is read-write.
			name:  "false booleans are not options",
			value: "type=bind,source=/s,destination=/d,ro=false,readonly=1,U=false,chown=false",
			want:  []Mount{{Source: "/s", Destination: "/d", Type: MountBind}},
		},
		{
			name:  "other options pass through",
			value: "type=bind,source=/s,destination=/d,bind-propagation=rslave",
			want:  []Mount{{Source: "/s", Destination: "/d", Type: MountBind, Options: []string{"bind-propagation=rslave"}}},
		},
		{
			name:  "the last source wins",
			value: "type=bind,source=/b1,source=/b2,destination=/b",
			want:  []Mount{{Source: "/b2", Destination: "/b", Type: MountBind}},
		},
		{
			name:  "Quadlet reads the value as CSV",
			value: `type=bind,"source=/a,b",destination=/d`,
			want:  []Mount{{Source: "/a,b", Destination: "/d", Type: MountBind}},
		},
		{name: "a volume mount", value: "type=volume,source=pg.volume,destination=/pg"},
		{name: "no type defaults to volume", value: "source=/srv,destination=/d"},
		{name: "the type key is case-sensitive", value: "Type=bind,source=/srv,destination=/d"},
		{name: "the type value is case-sensitive", value: "type=Bind,source=/srv,destination=/d"},
		{name: "no source", value: "type=bind,destination=/d"},
		{name: "an invalid relabel, which podman rejects", value: "type=bind,source=/s,destination=/d,relabel=Private"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := quadlet.Parse("web.container", strings.NewReader("[Container]\nImage=nginx\nMount="+tt.value+"\n"))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			u := FromParsed(f)
			for i := range tt.want {
				tt.want[i].Line, tt.want[i].Raw = 3, tt.value
			}
			if !reflect.DeepEqual(u.Mounts, tt.want) {
				t.Errorf("mounts =\n  %+v\nwant\n  %+v", u.Mounts, tt.want)
			}
			if len(u.Mounts) == 1 && u.Mounts[0].Key() != "Mount" {
				t.Errorf("key = %q, want Mount", u.Mounts[0].Key())
			}
		})
	}
}

func TestEmptyMountAndVolumeResetOnlyTheirOwnKey(t *testing.T) {
	// Verified against Podman 5.8.4: `Mount=` drops earlier Mount= entries but
	// keeps -v /v:/v, and `Volume=` drops -v but keeps earlier --mount ones.
	f, err := quadlet.Parse("web.container", strings.NewReader(`[Container]
Image=nginx
Mount=type=bind,source=/m1,destination=/m1
Volume=/v1:/v1
Mount=
Volume=/v2:/v2
Mount=type=bind,source=/m2,destination=/m2
Volume=
`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	var got []string
	for _, m := range FromParsed(f).Mounts {
		got = append(got, m.Key()+"="+m.Source)
	}
	if want := []string{"Mount=/m2"}; !reflect.DeepEqual(got, want) {
		t.Errorf("mounts = %v, want %v", got, want)
	}
}

func TestVolumeMountsReportTheVolumeKey(t *testing.T) {
	for _, value := range []string{"/srv:/data:Z", "/data", "pg.volume:/pg", "./rel:/d"} {
		if got := ParseMount(value, 1).Key(); got != "Volume" {
			t.Errorf("ParseMount(%q).Key() = %q, want Volume", value, got)
		}
	}
}

func unitNames(p *Project) []string {
	out := make([]string, 0, len(p.Units))
	for _, u := range p.Units {
		out = append(out, u.Name+"."+string(u.Kind))
	}
	return out
}
