package compose

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// TestUnsupportedIsInServiceOrder checks that the notes come out in the same
// order on every load. The loader keeps services in maps, so iterating them
// directly reorders the notes from one run to the next.
func TestUnsupportedIsInServiceOrder(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "compose.yaml")
	yaml := `
services:
  c: {image: docker.io/library/alpine:3.20, build: .}
  a: {image: docker.io/library/alpine:3.20, build: .}
  b: {image: docker.io/library/alpine:3.20, build: .}
  p2: {image: docker.io/library/alpine:3.20, profiles: [x]}
  p1: {image: docker.io/library/alpine:3.20, profiles: [x]}
`
	if err := os.WriteFile(path, []byte(yaml), 0o644); err != nil {
		t.Fatalf("writing compose: %v", err)
	}

	want := []string{"p1 profiles", "p2 profiles", "a build", "b build", "c build"}
	for i := 0; i < 20; i++ {
		p, err := Load(path)
		if err != nil {
			t.Fatalf("loading: %v", err)
		}
		var got []string
		for _, u := range p.Unsupported {
			got = append(got, u.Service+" "+u.Key)
		}
		if !slices.Equal(got, want) {
			t.Fatalf("load %d: notes in order %q, want %q", i, got, want)
		}
	}
}

// TestDisabledServiceGetsOneProfilesNote is the regression test for issue #36:
// a service disabled by a profile was reported twice, once by unsupportedFor's
// generic "profiles" handling (wrongly claiming the unit is generated
// unconditionally) and once by the precise note below it (correctly saying no
// unit was generated). Only the precise note should survive.
func TestDisabledServiceGetsOneProfilesNote(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "compose.yaml")
	yaml := `
services:
  worker:
    image: docker.io/library/busybox:1.36
    profiles: [batch]
    command: ["true"]
`
	if err := os.WriteFile(path, []byte(yaml), 0o644); err != nil {
		t.Fatalf("writing compose: %v", err)
	}

	p, err := Load(path)
	if err != nil {
		t.Fatalf("loading: %v", err)
	}

	var profileNotes []Unsupported
	for _, u := range p.Unsupported {
		if u.Key == "profiles" {
			profileNotes = append(profileNotes, u)
		}
	}
	if len(profileNotes) != 1 {
		t.Fatalf("got %d profiles notes for a disabled service, want 1: %+v", len(profileNotes), profileNotes)
	}
	if strings.Contains(profileNotes[0].Reason, "generated unconditionally") {
		t.Errorf("profiles note wrongly claims the unit was generated: %q", profileNotes[0].Reason)
	}
	if !strings.Contains(profileNotes[0].Reason, "No unit was generated") {
		t.Errorf("profiles note should say no unit was generated, got %q", profileNotes[0].Reason)
	}
}
