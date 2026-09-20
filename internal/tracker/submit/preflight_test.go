package submit

import (
	"errors"
	"testing"
)

func TestCheckHostGit_RealGitOnPath(t *testing.T) {
	version, err := CheckHostGit()
	if err != nil {
		t.Fatalf("CheckHostGit: %v (this environment's git must be >= %d.%d for the submit path to work at all)", err, MinGitMajor, MinGitMinor)
	}
	if version == "" {
		t.Error("CheckHostGit returned an empty version string alongside a nil error")
	}
}

func TestCheckHostGit_MissingGit(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	_, err := CheckHostGit()
	if !errors.Is(err, ErrGitMissing) {
		t.Errorf("err = %v, want ErrGitMissing", err)
	}
}
