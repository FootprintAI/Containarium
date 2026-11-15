package sdlcskills

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

const (
	testDigest = "cdfb63d2de1eb50a2e006863a2b2a6e7cf87f83af5671341476f73c0d526bbbc"
	testRef    = "b348a8258b4c075bc376d70313bb7787b2accc41"
)

func manifestText(lines ...string) string { return strings.Join(lines, "\n") + "\n" }

func validManifest() string {
	return manifestText(
		"# sdlc-skills manifest",
		"contract=1",
		"version=2026.11.0",
		"sha256="+testDigest,
		"source.sdlc=example/skills@"+testRef,
		"set.sdlc=architect,engineer",
		"set.qa=qa",
	)
}

func TestParseManifest(t *testing.T) {
	m, err := ParseManifest([]byte(validManifest()))
	if err != nil {
		t.Fatal(err)
	}
	want := Manifest{
		Contract: 1,
		Version:  "2026.11.0",
		SHA256:   testDigest,
		Sources:  []Source{{ID: "sdlc", Repo: "example/skills", Ref: testRef}},
		Sets:     map[string][]string{"sdlc": {"architect", "engineer"}, "qa": {"qa"}},
	}
	if !reflect.DeepEqual(m, want) {
		t.Errorf("ParseManifest =\n%+v\nwant\n%+v", m, want)
	}
	if got := m.SetIDs(); !reflect.DeepEqual(got, []string{"qa", "sdlc"}) {
		t.Errorf("SetIDs() = %v", got)
	}
	if got := m.Pin(); got != "example/skills@b348a8258b4c" {
		t.Errorf("Pin() = %q", got)
	}
}

// A newer bundle may carry keys this reader does not know. They are ignored,
// so an older daemon can read a newer manifest of the same contract.
func TestParseManifest_IgnoresUnknownKeys(t *testing.T) {
	m, err := ParseManifest([]byte(validManifest() + "built=2026-11-15T00:00:00Z\nfuture.key=whatever\n"))
	if err != nil {
		t.Fatalf("unknown keys refused: %v", err)
	}
	if m.Version != "2026.11.0" {
		t.Errorf("Version = %q", m.Version)
	}
}

func TestParseManifest_ContractTooNewIsATypedRefusal(t *testing.T) {
	text := strings.Replace(validManifest(), "contract=1", "contract=2", 1)
	_, err := ParseManifest([]byte(text))
	var tooNew *ContractTooNewError
	if !errors.As(err, &tooNew) {
		t.Fatalf("err = %v, want *ContractTooNewError", err)
	}
}

func TestParseManifest_Rejects(t *testing.T) {
	replace := func(old, new string) string { return strings.Replace(validManifest(), old, new, 1) }
	cases := map[string]struct{ text, want string }{
		"no contract":         {replace("contract=1\n", ""), "contract"},
		"contract not int":    {replace("contract=1", "contract=one"), "contract"},
		"contract zero":       {replace("contract=1", "contract=0"), "contract"},
		"no version":          {replace("version=2026.11.0\n", ""), "version"},
		"version shell":       {replace("version=2026.11.0", "version=1$(id)"), "version"},
		"version latest":      {replace("version=2026.11.0", "version=latest"), "version"},
		"no digest":           {replace("sha256="+testDigest+"\n", ""), "sha256"},
		"short digest":        {replace("sha256="+testDigest, "sha256=abc"), "sha256"},
		"duplicate key":       {validManifest() + "version=2026.12.0\n", "twice"},
		"duplicate set":       {validManifest() + "set.qa=qa\n", "twice"},
		"bad set id":          {validManifest() + "set.Q_A=other\n", "set id"},
		"bad namespace":       {validManifest() + "set.x=a b\n", "namespace"},
		"empty set":           {validManifest() + "set.x=\n", "no namespaces"},
		"namespace in 2 sets": {validManifest() + "set.x=qa\n", "one set"},
		"no sets":             {manifestText("contract=1", "version=1", "sha256="+testDigest), "no skill sets"},
		"malformed line":      {validManifest() + "what is this\n", "malformed"},
		"source without ref":  {validManifest() + "source.other=example/other\n", "source"},
		"source short ref":    {validManifest() + "source.other=example/other@abc\n", "commit"},
		"too large":           {validManifest() + "# " + strings.Repeat("x", maxManifestBytes) + "\n", "exceeds"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := ParseManifest([]byte(tc.text))
			if err == nil {
				t.Fatal("accepted")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

// Which namespaces a set covers comes from the bundle; which ids can be asked
// for by name comes from this binary's contract.
func TestManifest_ResolveSets(t *testing.T) {
	m, err := ParseManifest([]byte(validManifest() + "set.data=data\n"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := m.Namespaces([]string{"qa", "sdlc"})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"architect", "engineer", "qa"}; !reflect.DeepEqual(got, want) {
		t.Errorf("Namespaces = %v, want %v", got, want)
	}
	// In the contract, absent from this (older) release: names what it has.
	_, err = m.Namespaces([]string{"security"})
	var missing *SetNotInReleaseError
	if !errors.As(err, &missing) {
		t.Fatalf("err = %v, want *SetNotInReleaseError", err)
	}
	if !strings.Contains(err.Error(), "2026.11.0") || !strings.Contains(err.Error(), "data, qa, sdlc") {
		t.Errorf("message %q does not name the release and its sets", err)
	}
}
