package cmd

import (
	"bytes"
	"strings"
	"testing"

	"github.com/footprintai/containarium/internal/client"
	"github.com/footprintai/containarium/internal/sshkey"
	"github.com/footprintai/containarium/pkg/core/incus"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// inlineHostile lists the control bytes a tenant can smuggle into a
// free-text field. Each is wrapped so the escaped rendering is findable.
var inlineHostile = []struct {
	name string
	ctrl string
	want string // what escapeControl renders it as
}{
	{"ESC", "\x1b", `\x1b`},
	{"CR", "\r", `\r`},
	{"LF", "\n", `\n`},
	{"NUL", "\x00", `\x00`},
}

// assertInlineEscaped fails when out carries a raw control byte, or does
// not show the escaped marker (the cell must not simply vanish).
func assertInlineEscaped(t *testing.T, out, want string) {
	t.Helper()
	for _, raw := range []string{"\x1b", "\r", "\x00"} {
		if strings.Contains(out, raw) {
			t.Errorf("output carries raw control byte %q:\n%q", raw, out)
		}
	}
	if strings.Contains(out, "FORGED") && strings.Contains(out, "\nFORGED") {
		t.Errorf("tenant value forged its own output line:\n%q", out)
	}
	if !strings.Contains(out, "bad"+want+"FORGED") {
		t.Errorf("output does not show the escaped value bad%sFORGED:\n%q", want, out)
	}
}

// Every inline CLI table routes its tenant-supplied cells through
// escapeControl (#3453, follow-up to #3343).
func TestInlineCLITables_EscapeTenantSuppliedCells(t *testing.T) {
	type field struct {
		name   string
		render func(v string) string
	}
	render := func(fn func(w *bytes.Buffer)) string {
		var b bytes.Buffer
		fn(&b)
		return b.String()
	}
	fields := []field{
		{"secrets list: name", func(v string) string {
			return render(func(w *bytes.Buffer) { printSecretList(w, []*pb.SecretMetadata{{Name: v}}) })
		}},
		{"token list-revoked: reason", func(v string) string {
			return render(func(w *bytes.Buffer) { printRevokedTokens(w, []client.Revocation{{JTI: "j", Reason: v}}) })
		}},
		{"snapshot list: name", func(v string) string {
			return render(func(w *bytes.Buffer) { _ = printSnapshotList(w, []*pb.ContainerSnapshot{{Name: v}}) })
		}},
		{"volume list: name", func(v string) string {
			return render(func(w *bytes.Buffer) { _ = printVolumeList(w, []*pb.Volume{{Name: v, Pool: "p"}}) })
		}},
		{"volume list: pool", func(v string) string {
			return render(func(w *bytes.Buffer) { _ = printVolumeList(w, []*pb.Volume{{Name: "n", Pool: v}}) })
		}},
		{"ssh list: key name", func(v string) string {
			return render(func(w *bytes.Buffer) { _ = printSSHKeys(w, []sshkey.SSHKey{{Name: v, Fingerprint: "SHA256:x"}}) })
		}},
		{"agent list: id", func(v string) string {
			return render(func(w *bytes.Buffer) { printAgentSkillList(w, []*pb.AgentSkill{{Id: v}}) })
		}},
		{"agent list: description", func(v string) string {
			return render(func(w *bytes.Buffer) { printAgentSkillList(w, []*pb.AgentSkill{{Id: "i", Description: v}}) })
		}},
		{"crew list: id", func(v string) string {
			return render(func(w *bytes.Buffer) { printCrewList(w, []*pb.Crew{{Id: v}}) })
		}},
		{"crew list: description", func(v string) string {
			return render(func(w *bytes.Buffer) { printCrewList(w, []*pb.Crew{{Id: "i", Description: v}}) })
		}},
		{"scale-down status: box name", func(v string) string {
			return render(func(w *bytes.Buffer) { printScaleDownStatus(w, []incus.ContainerInfo{{Name: v, State: "Running"}}) })
		}},
	}
	for _, f := range fields {
		for _, h := range inlineHostile {
			t.Run(f.name+"/"+h.name, func(t *testing.T) {
				assertInlineEscaped(t, f.render("bad"+h.ctrl+"FORGED"), h.want)
			})
		}
	}
}

// Without control characters the printers keep their exact layout.
func TestInlineCLITables_PlainOutputUnchanged(t *testing.T) {
	var b bytes.Buffer
	printSecretList(&b, []*pb.SecretMetadata{{Name: "db-pass", Version: 3, UpdatedAt: "2026-10-01T00:00:00Z"}})
	want := "NAME                             VERSION  DELIVERY  UPDATED\n"
	if got := b.String(); !strings.HasPrefix(got, want) || !strings.Contains(got, "db-pass                          3 ") {
		t.Errorf("unexpected plain secrets output:\n%q", got)
	}
	b.Reset()
	printCrewList(&b, []*pb.Crew{{Id: "c1", Description: "plain text, unicode ✓"}})
	if !strings.Contains(b.String(), "plain text, unicode ✓") {
		t.Errorf("plain description altered:\n%q", b.String())
	}
}

// assertNoRawInline is the raw-byte half of assertInlineEscaped, for tables
// that truncate cells.
func assertNoRawInline(t *testing.T, out string) {
	t.Helper()
	for _, raw := range []string{"\x1b", "\r", "\x00"} {
		if strings.Contains(out, raw) {
			t.Errorf("output carries raw control byte %q:\n%q", raw, out)
		}
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "FORGED") {
			t.Errorf("tenant value forged its own line %q", line)
		}
	}
}
