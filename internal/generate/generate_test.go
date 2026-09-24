package generate

import (
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/MatrixMagician/quaddoc/internal/parse/compose"
	"github.com/MatrixMagician/quaddoc/internal/podmantest"
)

var update = flag.Bool("update", false, "rewrite golden files")

// fixtureProject loads the shared web-stack fixture.
func fixtureProject(t *testing.T) *compose.Project {
	t.Helper()
	p, err := compose.Load(filepath.Join("..", "..", "testdata", "fixtures", "webstack", "compose.yaml"))
	if err != nil {
		t.Fatalf("loading fixture: %v", err)
	}
	return p
}

// convertFixture converts the fixture and indexes the units by name.
func convertFixture(t *testing.T, opts Options) map[string]string {
	t.Helper()
	result := Convert(fixtureProject(t), opts)

	units := map[string]string{}
	for _, u := range result.Units {
		units[u.Name] = u.Content
	}
	return units
}

func TestConvertEmitsAUnitPerService(t *testing.T) {
	units := convertFixture(t, Options{Annotate: true})

	for _, want := range []string{
		"web.container", "db.container", "cache.container",
		"pgdata.volume", "cachedata.volume", "webstack-backend.network",
	} {
		if _, ok := units[want]; !ok {
			t.Errorf("no %s was generated; got %v", want, keys(units))
		}
	}
}

// TestGeneratedUnitsPassTheRealGenerator is the acceptance test for conversion.
//
// Golden files only prove the output has not changed; this proves Podman
// actually accepts it. The spec named `podman quadlet --dryrun`, which does not
// exist; the real entry point is the generator binary with QUADLET_UNIT_DIRS.
// See docs/spec-review.md finding F2.
func TestGeneratedUnitsPassTheRealGenerator(t *testing.T) {
	generator := podmantest.Generator(t)

	dir := t.TempDir()
	for name, content := range convertFixture(t, Options{Annotate: true}) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatalf("writing %s: %v", name, err)
		}
	}

	podmantest.AssertAccepts(t, generator, dir)
}

func TestNamedVolumesReferenceTheVolumeUnit(t *testing.T) {
	// A bare name would create an unmanaged volume with no dependency between
	// the units. The `.volume` suffix is what wires them together.
	units := convertFixture(t, Options{Annotate: true})

	if !strings.Contains(units["db.container"], "Volume=pgdata.volume:/var/lib/postgresql/data") {
		t.Errorf("db.container does not reference pgdata.volume:\n%s", units["db.container"])
	}
}

func TestEveryContainerJoinsTheSharedNetwork(t *testing.T) {
	// ADR-0001: the default network has DNS disabled, so a shared user-defined
	// network is required for sibling service names to resolve at all.
	units := convertFixture(t, Options{Annotate: true})

	for _, name := range []string{"web.container", "db.container", "cache.container"} {
		if !strings.Contains(units[name], "Network=webstack-backend.network") {
			t.Errorf("%s does not join the shared network:\n%s", name, units[name])
		}
	}
}

func TestHealthcheckIsTranslatedInFull(t *testing.T) {
	units := convertFixture(t, Options{Annotate: true})
	db := units["db.container"]

	for _, want := range []string{
		`HealthCmd=["CMD","pg_isready","-U","postgres"]`,
		"HealthInterval=10s",
		"HealthTimeout=5s",
		"HealthStartPeriod=30s",
		"HealthRetries=5",
	} {
		if !strings.Contains(db, want) {
			t.Errorf("db.container is missing %q:\n%s", want, db)
		}
	}
}

func TestUnlessStoppedIsExplained(t *testing.T) {
	// The mapping is lossy, so the unit must say so rather than quietly
	// substituting a policy that differs.
	units := convertFixture(t, Options{Annotate: true})
	web := units["web.container"]

	if !strings.Contains(web, "Restart=always") {
		t.Errorf("web.container should use Restart=always:\n%s", web)
	}
	if !strings.Contains(web, "unless-stopped") {
		t.Errorf("web.container does not explain the unless-stopped mapping:\n%s", web)
	}
}

func TestServiceHealthyDependencyIsExplained(t *testing.T) {
	// systemd ordering is not health gating. Letting that difference be
	// discovered in production is exactly the failure this tool exists to
	// prevent, so the unit must name Notify=healthy as the way to close it.
	units := convertFixture(t, Options{Annotate: true})
	web := units["web.container"]

	if !strings.Contains(web, "Notify=healthy") {
		t.Errorf("web.container does not mention Notify=healthy:\n%s", web)
	}
	if !strings.Contains(web, "After=db.service") {
		t.Errorf("web.container does not order after db:\n%s", web)
	}
}

func TestBindMountsAreFlaggedNotGuessed(t *testing.T) {
	// Whether a bind wants :z or :Z depends on project-wide sharing, which is
	// the rule engine's job. The generator must not guess.
	units := convertFixture(t, Options{Annotate: true})
	web := units["web.container"]

	if strings.Contains(web, ":ro,Z") || strings.Contains(web, "/certs:Z") {
		t.Errorf("the generator guessed at an SELinux label:\n%s", web)
	}
	if !strings.Contains(web, "quaddoc lint") {
		t.Errorf("the bind mount annotation does not point at the linter:\n%s", web)
	}
}

func TestUserAndGroupAreSplit(t *testing.T) {
	// Quadlet has separate User= and Group= keys, which it recombines into a
	// single --user USER:GROUP argument.
	units := convertFixture(t, Options{Annotate: true})
	cache := units["cache.container"]

	if !strings.Contains(cache, "User=999") || !strings.Contains(cache, "Group=999") {
		t.Errorf("cache.container did not split user 999:999:\n%s", cache)
	}
}

func TestEveryUnitHasAnInstallSection(t *testing.T) {
	// Otherwise QD022 would fire on our own output, which would be
	// embarrassing and correct.
	units := convertFixture(t, Options{Annotate: true})

	for name, content := range units {
		if strings.HasSuffix(name, ".volume") {
			continue // pulled in by the containers that mount them
		}
		if !strings.Contains(content, "[Install]") {
			t.Errorf("%s has no [Install] section:\n%s", name, content)
		}
	}
}

func TestNoTrailingWhitespaceInGeneratedUnits(t *testing.T) {
	units := convertFixture(t, Options{Annotate: true})

	for name, content := range units {
		for i, line := range strings.Split(content, "\n") {
			if len(line) > 0 && (line[len(line)-1] == ' ' || line[len(line)-1] == '\t') {
				t.Errorf("%s line %d has trailing whitespace: %q", name, i+1, line)
			}
		}
	}
}

func TestAnnotationsCanBeTurnedOff(t *testing.T) {
	plain := convertFixture(t, Options{Annotate: false})

	for name, content := range plain {
		if strings.Contains(content, "#") {
			t.Errorf("%s still carries comments with annotation off:\n%s", name, content)
		}
	}
}

func TestPodModeEmitsAPod(t *testing.T) {
	units := convertFixture(t, Options{Annotate: true, Pod: true})

	pod, ok := units["webstack.pod"]
	if !ok {
		t.Fatalf("no pod unit generated; got %v", keys(units))
	}
	// Ports belong to the pod, not to its members.
	if !strings.Contains(pod, "PublishPort=8080:80") {
		t.Errorf("the pod does not publish the web ports:\n%s", pod)
	}
	if strings.Contains(units["web.container"], "PublishPort=") {
		t.Errorf("a pod member should not publish ports itself:\n%s", units["web.container"])
	}
	if !strings.Contains(units["web.container"], "Pod=webstack.pod") {
		t.Errorf("web.container does not join the pod:\n%s", units["web.container"])
	}
}

func TestPodModeAlsoPassesTheRealGenerator(t *testing.T) {
	generator := podmantest.Generator(t)

	dir := t.TempDir()
	for name, content := range convertFixture(t, Options{Annotate: true, Pod: true}) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatalf("writing %s: %v", name, err)
		}
	}

	podmantest.AssertAccepts(t, generator, dir)
}

func TestUnsupportedKeysBecomeNotes(t *testing.T) {
	// The spec's non-goal is a partial port, not a silent one: a compose
	// feature we cannot translate must be reported.
	dir := t.TempDir()
	yaml := `
services:
  app:
    build: .
    profiles: ["debug"]
    image: docker.io/library/alpine:3.20
`
	path := filepath.Join(dir, "compose.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o644); err != nil {
		t.Fatalf("writing compose: %v", err)
	}

	p, err := compose.Load(path)
	if err != nil {
		t.Fatalf("loading: %v", err)
	}
	result := Convert(p, Options{Annotate: true})

	var sawBuild, sawProfiles bool
	for _, n := range result.Notes {
		if strings.Contains(n.Message, "build") {
			sawBuild = true
			if n.Unit != "app.container" {
				t.Errorf("build note has Unit %q, want %q so the CLI can name the service", n.Unit, "app.container")
			}
		}
		if strings.Contains(n.Message, "profiles") {
			sawProfiles = true
			if n.Unit != "app.container" {
				t.Errorf("profiles note has Unit %q, want %q so the CLI can name the service", n.Unit, "app.container")
			}
		}
	}
	if !sawBuild {
		t.Errorf("build: was dropped without a note; notes were %+v", result.Notes)
	}
	if !sawProfiles {
		t.Errorf("profiles: was dropped without a note; notes were %+v", result.Notes)
	}
}

func TestRenderRestart(t *testing.T) {
	tests := []struct {
		policy   string
		want     string
		wantNote bool
	}{
		{policy: "", want: "no"},
		{policy: "no", want: "no"},
		{policy: "always", want: "always"},
		{policy: "on-failure", want: "on-failure"},
		{policy: "on-failure:5", want: "on-failure", wantNote: true},
		{policy: "unless-stopped", want: "always", wantNote: true},
	}
	for _, tt := range tests {
		t.Run(tt.policy, func(t *testing.T) {
			got, note := renderRestart(tt.policy)
			if got != tt.want {
				t.Errorf("renderRestart(%q) = %q, want %q", tt.policy, got, tt.want)
			}
			if (note != "") != tt.wantNote {
				t.Errorf("renderRestart(%q) note = %q, wanted a note: %v", tt.policy, note, tt.wantNote)
			}
		})
	}
}

func TestHealthCommand(t *testing.T) {
	tests := []struct {
		name string
		test []string
		want string
	}{
		{name: "CMD form", test: []string{"CMD", "pg_isready", "-U", "postgres"}, want: `["CMD","pg_isready","-U","postgres"]`},
		{name: "CMD-SHELL form", test: []string{"CMD-SHELL", "curl -f http://localhost/ || exit 1"}, want: "curl -f http://localhost/ || exit 1"},
		{name: "empty", test: nil, want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := healthCommand(tt.test); got != tt.want {
				t.Errorf("healthCommand(%v) = %q, want %q", tt.test, got, tt.want)
			}
		})
	}
}

func TestConversionIsDeterministic(t *testing.T) {
	// Map iteration order must not leak into the output, or every conversion
	// produces a spurious diff.
	first := convertFixture(t, Options{Annotate: true})

	for i := 0; i < 10; i++ {
		again := convertFixture(t, Options{Annotate: true})
		for name, content := range first {
			if again[name] != content {
				t.Fatalf("%s differs between conversions", name)
			}
		}
	}
}

// convertTestdata converts a fixture under testdata/ without annotations, so
// the golden files hold only the keys under test.
func convertTestdata(t *testing.T, fixture string) *Result {
	t.Helper()
	p, err := compose.Load(filepath.Join("testdata", fixture, "compose.yaml"))
	if err != nil {
		t.Fatalf("loading fixture: %v", err)
	}
	return Convert(p, Options{})
}

// TestGolden pins the units generated for each fixture under testdata/: how
// values with spaces, quotes, `%` and `$` are written, and how compose
// networks translate. Each golden directory holds exactly the units generated,
// so it doubles as generator input and can be fed straight to
// `quadlet -dryrun` when reviewing a change to it.
func TestGolden(t *testing.T) {
	for _, fixture := range []string{"quoting", "networks", "coverage"} {
		t.Run(fixture, func(t *testing.T) {
			dir := filepath.Join("testdata", fixture)
			got := map[string]string{}
			for _, u := range convertTestdata(t, fixture).Units {
				got[u.Name] = u.Content
			}

			if *update {
				stale, _ := filepath.Glob(filepath.Join(dir, "*.*"))
				for _, path := range stale {
					if filepath.Base(path) != "compose.yaml" {
						_ = os.Remove(path)
					}
				}
				for name, content := range got {
					if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
						t.Fatalf("writing golden: %v", err)
					}
				}
				return
			}

			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatalf("reading %s: %v", dir, err)
			}
			for _, e := range entries {
				if e.Name() == "compose.yaml" {
					continue
				}
				if _, ok := got[e.Name()]; !ok {
					t.Errorf("golden %s was not generated (run with -update to remove it)", e.Name())
				}
			}
			for name, content := range got {
				want, err := os.ReadFile(filepath.Join(dir, name))
				if err != nil {
					t.Errorf("reading golden %s (run with -update to create it): %v", name, err)
					continue
				}
				if content != string(want) {
					t.Errorf("%s differs from its golden file.\n--- got ---\n%s\n--- want ---\n%s", name, content, want)
				}
			}
		})
	}
}

// dryRun feeds units to the real generator and returns its output.
func dryRun(t *testing.T, units []Unit) string {
	t.Helper()
	generator := podmantest.Generator(t)

	dir := t.TempDir()
	for _, u := range units {
		if err := os.WriteFile(filepath.Join(dir, u.Name), []byte(u.Content), 0o644); err != nil {
			t.Fatalf("writing %s: %v", u.Name, err)
		}
	}
	cmd := exec.Command(generator, "-dryrun", "-user")
	cmd.Env = append(os.Environ(), "QUADLET_UNIT_DIRS="+dir)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("the generator rejected the units: %v\n%s", err, out)
	}
	return string(out)
}

// TestNetworksReachPodmanIntact is the oracle for network translation: the
// real generator must turn each service's networks and network_mode into the
// --network arguments compose would have used, and each non-external compose
// network into a network of its own with its isolation intact.
func TestNetworksReachPodmanIntact(t *testing.T) {
	out := dryRun(t, convertTestdata(t, "networks").Units)

	tests := []struct {
		service string
		want    [][]string
		reject  []string
	}{
		{service: "hostnet", want: [][]string{{"--network", "host"}}},
		{service: "isolated", want: [][]string{{"--network", "none"}}},
		{service: "sidecar", want: [][]string{{"--network", "container:web"}}},
		{service: "joined", want: [][]string{{"--network", "container:legacy"}}},
		{service: "web", want: [][]string{
			{"--network", "networks_backend"},
			{"--network", "corp_lan"},
			{"--network", "public_net:alias=www,alias=site"},
		}},
		{service: "db", want: [][]string{
			{"--network", "networks_backend:ip=10.99.0.10"},
			{"-v", "pg_data:/var/lib/postgresql/data"},
			{"-v", "team_share:/shared"},
		}},
		{service: "networks-backend-network", want: [][]string{
			{"create", "--ignore", "--internal", "--subnet", "10.99.0.0/24", "networks_backend"},
		}},
		{service: "networks-frontend-network", want: [][]string{{"create", "--ignore", "public_net"}}, reject: []string{"--internal"}},
		{service: "data-volume", want: [][]string{{"create", "--ignore", "pg_data"}}},
	}
	for _, tt := range tests {
		argv := execStartArgv(t, out, tt.service)
		for _, want := range tt.want {
			if !containsRun(argv, want) {
				t.Errorf("%s: argv lacks %q\nargv: %q", tt.service, want, argv)
			}
		}
		for _, reject := range tt.reject {
			if containsRun(argv, []string{reject}) {
				t.Errorf("%s: argv has %q\nargv: %q", tt.service, reject, argv)
			}
		}
	}

	// An external network is the user's to create, so no unit may claim it.
	if strings.Contains(out, "---networks-corp-network.service---") {
		t.Errorf("the external corp network got a unit of its own:\n%s", out)
	}
}

// TestExternalObjectsAreNoted checks that the user is told to create the
// external objects the units rely on, by their real names.
func TestExternalObjectsAreNoted(t *testing.T) {
	var messages []string
	for _, n := range convertTestdata(t, "networks").Notes {
		messages = append(messages, n.Message)
	}
	all := strings.Join(messages, "\n")
	for _, want := range []string{"podman network create corp_lan", "podman volume create team_share"} {
		if !strings.Contains(all, want) {
			t.Errorf("no note says %q; notes were:\n%s", want, all)
		}
	}
}

// TestCommentsNameTheRealObjects checks the annotations against what
// NetworkName= and VolumeName= make Podman create: the name compose gives the
// object, not Quadlet's `systemd-` default that those keys override.
func TestCommentsNameTheRealObjects(t *testing.T) {
	p, err := compose.Load(filepath.Join("testdata", "networks", "compose.yaml"))
	if err != nil {
		t.Fatalf("loading fixture: %v", err)
	}
	units := map[string]string{}
	for _, u := range Convert(p, Options{Annotate: true}).Units {
		units[u.Name] = u.Content
	}

	for unit, want := range map[string]string{
		"networks-frontend.network": "Podman name the network `public_net`",
		"data.volume":               "Podman name the volume `pg_data`",
		"db.container":              "materialises as a volume called `pg_data`",
	} {
		// Join the comment lines back up, so wrapping cannot split a phrase.
		if !strings.Contains(strings.ReplaceAll(units[unit], "\n# ", " "), want) {
			t.Errorf("%s does not say %q:\n%s", unit, want, units[unit])
		}
	}
}

// TestQuotedValuesReachPodmanIntact is the oracle for the quoting: it runs the
// real generator and checks the argv systemd would hand to podman, after its
// own unquoting and specifier and variable expansion.
func TestQuotedValuesReachPodmanIntact(t *testing.T) {
	out := dryRun(t, convertTestdata(t, "quoting").Units)

	tests := []struct {
		service string
		want    [][]string
	}{
		{service: "app", want: [][]string{
			{`--entrypoint=["/bin/sh","-c"]`},
			{"--env", "DATE_FMT=%Y-%m-%d"},
			{"--env", "DOLLAR=cost $HOME"},
			{"--env", "GREETING=hello world"},
			{"--env", "HOMEISH=50%h"},
			{"--env", "PCT=100%"},
			{"--env", `QUOTED=say "hi"`},
			{"--sysctl", "net.ipv4.ping_group_range=0 1000"},
			{"--label", "description=a label with spaces"},
			{"--health-cmd", `["CMD","test","-f","/tmp/my file"]`},
			{"docker.io/library/alpine:3.20", `echo "$0" "$1"; sleep inf`, "hello world", "&&"},
		}},
		{service: "shell", want: [][]string{
			{"--entrypoint=/entrypoint.sh"},
			{"--health-cmd", "test -f /tmp/ready || exit 1"},
			{"docker.io/library/alpine:3.20", "sh", "-c", "echo one two; sleep inf"},
		}},
	}
	for _, tt := range tests {
		argv := execStartArgv(t, out, tt.service)
		for _, want := range tt.want {
			if !containsRun(argv, want) {
				t.Errorf("%s: argv lacks %q\nargv: %q", tt.service, want, argv)
			}
		}
	}
}

// execStartArgv finds a service's ExecStart= in dry-run output and decodes it
// the way systemd does. Quadlet writes each word bare or wholly double-quoted
// with C escapes, so words split on spaces and unquote with strconv. An
// unescaped specifier or variable becomes a marker rather than a guess, so a
// missing escape shows up as a mismatch.
func execStartArgv(t *testing.T, dryrun, service string) []string {
	t.Helper()
	_, unit, found := strings.Cut(dryrun, "---"+service+".service---")
	if !found {
		t.Fatalf("no %s.service in the dry-run output:\n%s", service, dryrun)
	}
	_, line, found := strings.Cut(unit, "\nExecStart=")
	if !found {
		t.Fatalf("%s.service has no ExecStart=:\n%s", service, unit)
	}
	line, _, _ = strings.Cut(line, "\n")

	var argv []string
	for _, word := range strings.Fields(line) {
		if strings.HasPrefix(word, `"`) {
			unquoted, err := strconv.Unquote(word)
			if err != nil {
				t.Fatalf("cannot unquote %s: %v", word, err)
			}
			word = unquoted
		}
		argv = append(argv, expand(word))
	}
	return argv
}

// expand applies systemd's `%%` and `$$` escapes, marking anything a specifier
// or variable would have replaced.
func expand(word string) string {
	var b strings.Builder
	for i := 0; i < len(word); i++ {
		c := word[i]
		if c == '%' || c == '$' {
			if i+1 < len(word) && word[i+1] == c {
				b.WriteByte(c)
				i++
			} else {
				b.WriteString("<expanded>")
			}
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}

// containsRun reports whether want appears in argv as consecutive elements.
func containsRun(argv, want []string) bool {
	for i := 0; i+len(want) <= len(argv); i++ {
		match := true
		for j := range want {
			if argv[i+j] != want[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// TestCoverageReachesPodmanIntact is the oracle for the compose keys that
// were once dropped: the real generator must hand podman the flags compose
// would have used.
func TestCoverageReachesPodmanIntact(t *testing.T) {
	out := dryRun(t, convertTestdata(t, "coverage").Units)

	argv := execStartArgv(t, out, "app")
	for _, want := range [][]string{
		{"--name", "my-app"},
		{"--network", "coverage_default:alias=app"},
		{"--add-host", "db.internal:10.0.0.5"},
		{"--pid=host", "--ipc=host"},
		{"--init"},
		{"--userns", "keep-id"},
		{"--stop-timeout", "90"},
		{"--dns-search", "example.internal"},
		{"--ulimit", "nofile=65536"},
		{"--ulimit", "nproc=1024:2048"},
		{"--memory", "536870912"},
		{"--pull", "always"},
		{"--log-driver", "journald"},
		{"--log-opt", "tag=my app"},
		{"--annotation", "io.example=1"},
		{"--pids-limit", "100"},
		{"--health-cmd", "none"},
		{"--tmpfs", "/run:size=67108864,mode=1777"},
		{"-v", "data:/data:nocopy"},
		{"-v", "/srv/cfg:/cfg:rshared"},
		{"--env", "EXPLICIT_EMPTY="},
	} {
		if !containsRun(argv, want) {
			t.Errorf("app: argv lacks %q\nargv: %q", want, argv)
		}
	}
	for _, word := range argv {
		// An unresolved `- VAR` leaves the variable unset in compose; an
		// empty assignment is not the same thing.
		if strings.HasPrefix(word, "QUADDOC_TEST_UNSET_21") {
			t.Errorf("app: the unresolved variable reached podman as %q", word)
		}
		// A long-syntax tmpfs is not a persistent anonymous volume.
		if word == "/run" {
			t.Errorf("app: /run was mounted as a volume\nargv: %q", argv)
		}
	}

	_, app, _ := strings.Cut(out, "---app.service---")
	app, _, _ = strings.Cut(app, "\n---")
	if !strings.Contains(app, "\nWants=db.service\n") || strings.Contains(app, "Requires=db.service") {
		t.Errorf("app.service should want db, which compose marked required: false:\n%s", app)
	}
	if !strings.Contains(app, "\nRequires=cache.service\n") {
		t.Errorf("app.service should still require cache:\n%s", app)
	}
}

// TestUntranslatableKeysAreNoted checks that each compose key with no Quadlet
// equivalent is reported against the unit it was dropped from.
func TestUntranslatableKeysAreNoted(t *testing.T) {
	notes := convertTestdata(t, "coverage").Notes

	for _, want := range []struct{ unit, text string }{
		{"app.container", `"security_opt"`},
		{"app.container", `"cgroup_parent"`},
		{"app.container", "QUADDOC_TEST_UNSET_21"},
		{"app.container", "on-failure:3"},
		{"app.container", "TimeoutStopSec="},
		{"db.container", `"pid"`},
		{"db.container", `"ipc"`},
		{"db.container", `"pull_policy"`},
		{"db.container", `"healthcheck.start_interval"`},
	} {
		found := false
		for _, n := range notes {
			if n.Unit == want.unit && strings.Contains(n.Message, want.text) {
				found = true
			}
		}
		if !found {
			t.Errorf("no note on %s mentions %s; notes were:\n%+v", want.unit, want.text, notes)
		}
	}
	for _, n := range notes {
		if n.Unit == "app.container" && (strings.Contains(n.Message, `"pid"`) || strings.Contains(n.Message, `"ipc"`)) {
			t.Errorf("pid: host and ipc: host are translated, yet were noted: %s", n.Message)
		}
	}
}

func keys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
