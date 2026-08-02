package podmantest

import "testing"

func TestVersionBefore(t *testing.T) {
	// The comparison decides whether the acceptance tests run at all, so an
	// off-by-one here either skips checks that should run or runs them against
	// a Podman that cannot support them.
	tests := []struct {
		name   string
		v      Version
		other  Version
		before bool
	}{
		{name: "older major", v: Version{4, 9}, other: Version{5, 0}, before: true},
		{name: "same version", v: Version{5, 0}, other: Version{5, 0}, before: false},
		{name: "newer minor", v: Version{5, 8}, other: Version{5, 0}, before: false},
		{name: "older minor", v: Version{5, 0}, other: Version{5, 8}, before: true},
		{name: "newer major, older minor", v: Version{6, 0}, other: Version{5, 9}, before: false},
		{name: "double-digit minor", v: Version{5, 10}, other: Version{5, 9}, before: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.v.Before(tt.other); got != tt.before {
				t.Errorf("%s.Before(%s) = %v, want %v", tt.v, tt.other, got, tt.before)
			}
		})
	}
}

func TestVersionString(t *testing.T) {
	if got := (Version{5, 8}).String(); got != "5.8" {
		t.Errorf("String() = %q, want \"5.8\"", got)
	}
}

func TestPodmanVersionOnThisSystem(t *testing.T) {
	// Not asserting a specific version, which would break on every upgrade,
	// but the parse must succeed wherever podman is installed at all.
	if GeneratorPath() == "" {
		t.Skip("podman not installed")
	}

	version, ok := PodmanVersion()
	if !ok {
		t.Fatal("podman is installed but its version could not be parsed")
	}
	if version.Major == 0 {
		t.Errorf("parsed an implausible version: %s", version)
	}
}
