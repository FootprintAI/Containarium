package sshdpolicy

import (
	"strings"
	"testing"
)

func TestDirective(t *testing.T) {
	tests := []struct {
		name, config, key, def, want string
	}{
		{"absent uses default", "Port 22\n", "PasswordAuthentication", "yes", "yes"},
		{"simple", "PasswordAuthentication no\n", "PasswordAuthentication", "yes", "no"},
		{"case insensitive key", "passwordauthentication NO\n", "PasswordAuthentication", "yes", "NO"},
		{"comments ignored", "#PasswordAuthentication yes\nPasswordAuthentication no\n", "PasswordAuthentication", "yes", "no"},
		// OpenSSH takes the FIRST occurrence, not the last.
		{"first occurrence wins", "PasswordAuthentication no\nPasswordAuthentication yes\n", "PasswordAuthentication", "yes", "no"},
		{"match block ignored", "Match User bob\nPasswordAuthentication yes\n", "PasswordAuthentication", "no", "no"},
		{"directive before match still counts", "PasswordAuthentication no\nMatch User bob\nPasswordAuthentication yes\n", "PasswordAuthentication", "yes", "no"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := Directive(tc.config, tc.key, tc.def); got != tc.want {
				t.Errorf("Directive() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestMerge_DropInsPrecedeMainInLexicalOrder(t *testing.T) {
	merged := Merge("PasswordAuthentication yes\n", []DropIn{
		{Name: "90-later.conf", Content: "PasswordAuthentication yes\n"},
		{Name: "README", Content: "PasswordAuthentication no\n"}, // not .conf: ignored, as sshd does
		{Name: "10-first.conf", Content: "PasswordAuthentication no\n"},
	})
	if got := Directive(merged, "PasswordAuthentication", "yes"); got != "no" {
		t.Fatalf("lexically-first drop-in must win under first-match-wins; merged:\n%s", merged)
	}
	if strings.Index(merged, "10-first") > strings.Index(merged, "90-later") && strings.Contains(merged, "10-first") {
		t.Error("drop-ins not in lexical order")
	}
}

// The managed drop-in must itself evaluate as compliant, and must win over
// every drop-in a distro or cloud-init ships (they are 50-*.conf).
func TestDropInContent_IsCompliantAndSortsFirst(t *testing.T) {
	cloudInit := DropIn{Name: "50-cloud-init.conf", Content: "PasswordAuthentication yes\n"}
	ours := DropIn{Name: DropInName, Content: string(DropInContent())}
	r := Evaluate(Merge("PasswordAuthentication yes\n", []DropIn{cloudInit, ours}))
	if !r.Compliant() {
		t.Fatalf("managed drop-in must beat the cloud-init drop-in and the main file: %v", r.Violations)
	}
	if DropInName >= cloudInit.Name {
		t.Errorf("%s must sort before %s", DropInName, cloudInit.Name)
	}
	if !ManagedDropInIntact([]DropIn{cloudInit, ours}) {
		t.Error("ManagedDropInIntact must accept the managed content verbatim")
	}
}

func TestEvaluate(t *testing.T) {
	tests := []struct {
		name   string
		config string
		want   []string // violation strings; nil = compliant
	}{
		{"image default is non-compliant", "Port 22\n", []string{"PasswordAuthentication=yes", "KbdInteractiveAuthentication=yes"}},
		{"password off alone leaves PAM prompt open", "PasswordAuthentication no\n", []string{"KbdInteractiveAuthentication=yes"}},
		{"fully hardened", "PasswordAuthentication no\nKbdInteractiveAuthentication no\n", nil},
		{"empty passwords permitted", "PasswordAuthentication no\nKbdInteractiveAuthentication no\nPermitEmptyPasswords yes\n", []string{"PermitEmptyPasswords=yes"}},
		{"case-insensitive values", "passwordauthentication NO\nkbdinteractiveauthentication No\n", nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := Evaluate(tc.config)
			var got []string
			for _, v := range r.Violations {
				got = append(got, v.String())
			}
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Errorf("violations = %v, want %v", got, tc.want)
			}
			if r.Compliant() != (tc.want == nil) {
				t.Errorf("Compliant() = %v, want %v", r.Compliant(), tc.want == nil)
			}
		})
	}
}

func TestManagedDropInIntact(t *testing.T) {
	if ManagedDropInIntact(nil) {
		t.Error("absent drop-in must not count as intact")
	}
	if ManagedDropInIntact([]DropIn{{Name: DropInName, Content: "PasswordAuthentication yes\n"}}) {
		t.Error("a rewritten drop-in must not count as intact")
	}
}

func TestPorts(t *testing.T) {
	cases := []struct {
		name, cfg string
		want      []int
	}{
		{"default when absent", "PermitRootLogin no\n", []int{22}},
		{"single", "Port 2222\n", []int{2222}},
		{"additive across lines and files", "Port 22\n#Port 99\nPort 2200\n", []int{22, 2200}},
		{"case-insensitive keyword", "port 8022\n", []int{8022}},
		{"stops at Match", "Port 22\nMatch User x\nPort 9999\n", []int{22}},
		{"match before any port keeps the default", "Match User x\nPort 9999\n", []int{22}},
		{"garbage ignored", "Port abc\nPort 70000\nPort 0\n", []int{22}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Ports(c.cfg)
			if len(got) != len(c.want) {
				t.Fatalf("Ports = %v, want %v", got, c.want)
			}
			for i := range got {
				if got[i] != c.want[i] {
					t.Fatalf("Ports = %v, want %v", got, c.want)
				}
			}
		})
	}
}
