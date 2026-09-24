package compose

import (
	"os"
	"path/filepath"
	"slices"
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

	want := []string{"p1 profiles", "p1 profiles", "p2 profiles", "p2 profiles", "a build", "b build", "c build"}
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
