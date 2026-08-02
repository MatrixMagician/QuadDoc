package ir

import (
	"os"
	"path/filepath"
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
	// Case-insensitive, as systemd is.
	if got := u.KeyLine("image"); got != 3 {
		t.Errorf("KeyLine is case-sensitive; got %d for lowercase", got)
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

func unitNames(p *Project) []string {
	out := make([]string, 0, len(p.Units))
	for _, u := range p.Units {
		out = append(out, u.Name+"."+string(u.Kind))
	}
	return out
}
