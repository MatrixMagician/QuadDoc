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

func TestContinuationJoinsWithSpace(t *testing.T) {
	// Verified against Podman 5.8.4: a continued PodmanArgs= reaches the
	// generated ExecStart as `--label app=web tier=front`, so fragments are
	// joined with a single space.
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

func TestSectionAndKeyMatchingIsCaseInsensitive(t *testing.T) {
	f, _ := parseFixture(t, "web.container")

	if _, ok := f.Lookup("container", "image"); !ok {
		t.Error("lookup should match section and key case-insensitively, as systemd does")
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

func TestEscapedBackslashDoesNotContinue(t *testing.T) {
	// An even number of trailing backslashes is an escaped backslash, not a
	// continuation marker.
	f, err := Parse("mem", strings.NewReader("[Container]\nExec=printf 'a\\\\'\nImage=busybox\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if _, ok := f.Lookup("Container", "Image"); !ok {
		t.Error("Image was swallowed as a continuation of the escaped backslash")
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
