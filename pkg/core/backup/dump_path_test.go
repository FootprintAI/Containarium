package backup

import (
	"regexp"
	"strings"
	"testing"
)

// Each staging name is unguessable: a fresh random suffix per call (#3680).
func TestStagingDumpPathIsFreshAndUnguessable(t *testing.T) {
	a, err := stagingDumpPath("backup", "alice-db-20260101T000000Z")
	if err != nil {
		t.Fatal(err)
	}
	b, err := stagingDumpPath("backup", "alice-db-20260101T000000Z")
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatalf("two calls gave the same path %q; want a fresh name each time", a)
	}
	re := regexp.MustCompile(`^/tmp/containarium-backup-alice-db-20260101T000000Z-[0-9a-f]{32}\.dump$`)
	if !re.MatchString(a) {
		t.Errorf("path %q does not match the expected shape with a 16-byte random suffix", a)
	}
	if strings.Contains(a, "..") {
		t.Errorf("path %q contains a traversal component", a)
	}
}

func TestStagingDumpPathCarriesItsKind(t *testing.T) {
	for _, kind := range []string{"backup", "restore", "verify"} {
		p, err := stagingDumpPath(kind, "x")
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(p, "/tmp/containarium-"+kind+"-x-") {
			t.Errorf("kind %s: path %q lacks the expected prefix", kind, p)
		}
	}
}
