package quadlet

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func parseFixture(t *testing.T, name string) (*File, string) {
	t.Helper()
	path := filepath.Join("testdata", name)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	f, err := Parse(path, strings.NewReader(string(raw)))
	if err != nil {
		t.Fatalf("parsing %s: %v", name, err)
	}
	return f, string(raw)
}

// TestRoundTrip is the load-bearing test for the fix engine: an unmodified file
// must render back byte for byte, or applying a fix to one line would silently
// reformat the rest of the file.
func TestRoundTrip(t *testing.T) {
	entries, err := os.ReadDir("testdata")
	if err != nil {
		t.Fatalf("reading testdata: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("no fixtures found; the round-trip test would vacuously pass")
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		t.Run(e.Name(), func(t *testing.T) {
			f, original := parseFixture(t, e.Name())
			if got := f.Render(); got != original {
				t.Errorf("round trip changed the file.\n--- original ---\n%q\n--- rendered ---\n%q", original, got)
			}
		})
	}
}

func TestRepeatedKeysAreAList(t *testing.T) {
	f, _ := parseFixture(t, "web.container")

	got := f.Values("Container", "Volume")
	want := []string{
		"/srv/site:/usr/share/nginx/html:Z",
		"/srv/certs:/etc/nginx/certs:ro",
	}
	if len(got) != len(want) {
		t.Fatalf("Volume count = %d, want %d (%q)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("Volume[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestContinuationKeepsTheSpaceBeforeTheBackslash(t *testing.T) {
	// Verified against Podman 5.8.4: a continued PodmanArgs= reaches the
	// generated ExecStart as `--label app=web tier=front`. The spaces come
	// from before each backslash; the generator adds none of its own.
	f, _ := parseFixture(t, "web.container")

	got, ok := f.Lookup("Container", "PodmanArgs")
	if !ok {
		t.Fatal("PodmanArgs not found")
	}
	if want := "--label app=web tier=front"; got != want {
		t.Errorf("PodmanArgs = %q, want %q", got, want)
	}
}

func TestHashInsideValueIsNotAComment(t *testing.T) {
	f, _ := parseFixture(t, "web.container")

	for _, v := range f.Values("Container", "Environment") {
		if strings.HasPrefix(v, "MOTD=") {
			if want := "MOTD=welcome # not a comment"; v != want {
				t.Errorf("Environment = %q, want %q", v, want)
			}
			return
		}
	}
	t.Fatal("MOTD environment entry not found")
}

func TestBothCommentMarkers(t *testing.T) {
	f, _ := parseFixture(t, "web.container")

	var hash, semi bool
	for _, l := range f.Lines {
		if l.Kind != LineComment {
			continue
		}
		switch {
		case strings.HasPrefix(strings.TrimSpace(l.Raw[0]), "#"):
			hash = true
		case strings.HasPrefix(strings.TrimSpace(l.Raw[0]), ";"):
			semi = true
		}
	}
	if !hash || !semi {
		t.Errorf("comment markers recognised: # = %v, ; = %v; want both", hash, semi)
	}
}

func TestRepeatedSectionContinues(t *testing.T) {
	// systemd treats a second [Container] as a continuation of the first,
	// so entries from both occurrences belong to the same section.
	f, _ := parseFixture(t, "repeated-section.container")

	if got := len(f.Section("Container")); got != 3 {
		t.Errorf("Container entries = %d, want 3", got)
	}
	if _, ok := f.Lookup("Container", "Environment"); !ok {
		t.Error("Environment from the second [Container] was lost")
	}
}

func TestEmptySectionIsPresent(t *testing.T) {
	// An empty [Install] is a statement of intent and must be distinguishable
	// from an absent one: QD022 turns on exactly that difference.
	f, _ := parseFixture(t, "repeated-section.container")

	if !f.HasSection("Install") {
		t.Error("HasSection(Install) = false for an empty but present section")
	}
	if got := len(f.Section("Install")); got != 0 {
		t.Errorf("Install entries = %d, want 0", got)
	}
}

func TestMalformedLineIsPreservedNotDropped(t *testing.T) {
	// A linter that refuses to parse is useless on the malformed files a user
	// most needs linted, so an unrecognised line is kept and reported.
	f, _ := parseFixture(t, "malformed.container")

	var unknown int
	for _, l := range f.Lines {
		if l.Kind == LineUnknown {
			unknown++
		}
	}
	if unknown != 1 {
		t.Errorf("unknown lines = %d, want 1", unknown)
	}
	// Parsing must continue past the bad line.
	if _, ok := f.Lookup("Container", "Volume"); !ok {
		t.Error("parsing stopped at the malformed line")
	}
}

func TestSectionAndKeyMatchingIsExact(t *testing.T) {
	// Verified against Podman 5.8.4: a unit with `[container]` and `image=`
	// is rejected with "no Image or Rootfs key specified".
	f, err := Parse("mem", strings.NewReader("[container]\nimage=nginx\n[Container]\nimage=busybox\n[install]\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	for _, section := range []string{"Container", "container"} {
		if v, ok := f.Lookup(section, "Image"); ok {
			t.Errorf("Lookup(%s, Image) = %q, want no match for a lowercase key", section, v)
		}
	}
	if v, _ := f.Lookup("container", "image"); v != "nginx" {
		t.Errorf("Lookup(container, image) = %q, want nginx", v)
	}
	if f.HasSection("Install") {
		t.Error("HasSection(Install) = true for a file with only [install]")
	}
}

func TestLookupTakesTheLastValue(t *testing.T) {
	f, err := Parse("mem", strings.NewReader("[Container]\nImage=first\nImage=second\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	got, _ := f.Lookup("Container", "Image")
	if want := "second"; got != want {
		t.Errorf("Lookup = %q, want %q (systemd is last-one-wins for scalar keys)", got, want)
	}
}

func TestLineNumbersAreReported(t *testing.T) {
	// Findings cite line numbers, so they must survive continuations.
	f, _ := parseFixture(t, "web.container")

	for _, e := range f.Entries() {
		if e.Key != "PodmanArgs" {
			continue
		}
		// PodmanArgs starts on line 17 of the fixture.
		if e.Line != 17 {
			t.Errorf("PodmanArgs line = %d, want 17", e.Line)
		}
		return
	}
	t.Fatal("PodmanArgs entry not found")
}

func TestContinuationMatchesTheGenerator(t *testing.T) {
	// Each case was checked against /usr/libexec/podman/quadlet -dryrun
	// (Podman 5.8.4) by reading the generated ExecStart.
	tests := []struct {
		name       string
		text       string
		wantValue  string
		wantVolume bool
	}{
		{
			name: "comment and blank lines inside a continuation are skipped",
			text: `[Container]
Exec=echo one \
# c1
  ; c2
  two \

  three
Volume=/a:/a
`,
			wantValue:  "echo one two three",
			wantVolume: true,
		},
		{
			name: "fragments are concatenated with leading space trimmed",
			text: `[Container]
Exec=ab \
   cd\
ef
`,
			wantValue: "ab cdef",
		},
		{
			name:      "whitespace after the backslash still continues",
			text:      "[Container]\nExec=ab\\  \ncd\n",
			wantValue: "abcd",
		},
		{
			// Quadlet does not treat a doubled backslash as an escape here: the
			// next line is swallowed, and the Volume= with it.
			name: "a doubled trailing backslash still continues",
			text: `[Container]
Exec=echo one two \\
Volume=/srv/x:/x
`,
			wantValue: `echo one two \Volume=/srv/x:/x`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := Parse("mem", strings.NewReader(tt.text))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if got, _ := f.Lookup("Container", "Exec"); got != tt.wantValue {
				t.Errorf("Exec = %q, want %q", got, tt.wantValue)
			}
			if _, ok := f.Lookup("Container", "Volume"); ok != tt.wantVolume {
				t.Errorf("Volume present = %v, want %v", ok, tt.wantVolume)
			}
			if got := f.Render(); got != tt.text {
				t.Errorf("Render = %q, want the input back", got)
			}
		})
	}
}

func TestLineNumbersSurviveSkippedContinuationLines(t *testing.T) {
	f, err := Parse("mem", strings.NewReader("[Container]\nExec=a \\\n# c\n  b\nVolume=/a:/a\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := f.Entries(); len(got) != 2 || got[1].Key != "Volume" || got[1].Line != 5 {
		t.Errorf("entries = %+v, want Volume second, on line 5", got)
	}
}

func TestFileWithoutTrailingNewlineRoundTrips(t *testing.T) {
	f, original := parseFixture(t, "no-trailing-newline.container")
	if got := f.Render(); got != original {
		t.Errorf("Render = %q, want %q", got, original)
	}
}

func TestEmptyInput(t *testing.T) {
	f, err := Parse("mem", strings.NewReader(""))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := f.Render(); got != "" {
		t.Errorf("Render of empty input = %q, want empty", got)
	}
	if len(f.Entries()) != 0 {
		t.Error("empty input produced entries")
	}
}
