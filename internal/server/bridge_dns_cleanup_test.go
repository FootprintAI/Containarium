package server

import (
	"errors"
	"testing"
)

// #2734 (slice C of #2263): on upgrade the daemon strips the bridge DNS record
// earlier daemons wrote and leaves every other raw.dnsmasq line alone
// (decision Q36 on #2727).
func TestStripBridgeDNSRecord(t *testing.T) {
	const old = "address=/example.com/10.0.3.5\nserver=/ssh.example.com/#\nserver=/api.example.com/#"
	cases := []struct {
		name, raw, base, ssh string
		want                 string
		changed              bool
	}{
		{name: "no base domain (BYOC) leaves the value alone", raw: old, base: "", ssh: "ssh.example.com", want: old},
		{name: "invalid base domain leaves the value alone", raw: old, base: "exa mple.com", want: old},
		{name: "empty value", raw: "", base: "example.com", want: ""},
		{
			name: "no address line: carve-out-shaped lines are kept",
			raw:  "server=/ssh.example.com/#\nserver=/api.example.com/#",
			base: "example.com", ssh: "ssh.example.com",
			want: "server=/ssh.example.com/#\nserver=/api.example.com/#",
		},
		{name: "the whole daemon record goes and the key is unset", raw: old, base: "example.com", ssh: "ssh.example.com", want: "", changed: true},
		{
			name: "only blank lines left over: the key is unset",
			raw:  "address=/example.com/10.0.3.5\n\nserver=/ssh.example.com/#\n",
			base: "example.com", ssh: "ssh.example.com",
			want: "", changed: true,
		},
		{
			name: "operator lines survive byte for byte, in order",
			raw:  "# operator\ndhcp-option=6,10.0.3.1\naddress=/example.com/10.0.3.5\nserver=/ssh.example.com/#\naddress=/other.test/10.0.3.9\n  server=/corp.internal/10.1.1.1  \nserver=/unrelated.test/#",
			base: "example.com", ssh: "ssh.example.com",
			want:    "# operator\ndhcp-option=6,10.0.3.1\naddress=/other.test/10.0.3.9\n  server=/corp.internal/10.1.1.1  \nserver=/unrelated.test/#",
			changed: true,
		},
		{
			name: "ssh host outside the base domain is still the daemon's carve-out",
			raw:  "address=/example.com/10.0.3.5\nserver=/ssh.region.test/#\nserver=/keep.region.test/#",
			base: "example.com", ssh: "ssh.region.test",
			want: "server=/keep.region.test/#", changed: true,
		},
		{
			name: "names at or under the base domain go; a suffix that is not a label boundary stays",
			raw:  "address=/example.com/10.0.3.5\nserver=/example.com/#\nserver=/a.b.example.com/#\nserver=/notexample.com/#",
			base: "example.com",
			want: "server=/notexample.com/#", changed: true,
		},
		{
			name: "case and a trailing dot do not hide the record",
			raw:  "address=/Example.COM./10.0.3.5\nserver=/API.example.com./#",
			base: "example.com.",
			want: "", changed: true,
		},
		{
			name: "a server line with an upstream address is an operator line",
			raw:  "address=/example.com/10.0.3.5\nserver=/api.example.com/10.1.1.1",
			base: "example.com",
			want: "server=/api.example.com/10.1.1.1", changed: true,
		},
		{
			name: "a multi-domain address line is not the daemon's shape",
			raw:  "address=/example.com/other.test/10.0.3.5",
			base: "example.com",
			want: "address=/example.com/other.test/10.0.3.5",
		},
		{
			name: "an address line for a subdomain is not the record",
			raw:  "address=/app.example.com/10.0.3.7\nserver=/api.example.com/#",
			base: "example.com",
			want: "address=/app.example.com/10.0.3.7\nserver=/api.example.com/#",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, changed := stripBridgeDNSRecord(tc.raw, tc.base, tc.ssh)
			if got != tc.want || changed != tc.changed {
				t.Fatalf("stripBridgeDNSRecord(%q, %q, %q)\n got: %q changed=%v\nwant: %q changed=%v", tc.raw, tc.base, tc.ssh, got, changed, tc.want, tc.changed)
			}
			// Idempotent: a second pass over the result changes nothing.
			if again, changed2 := stripBridgeDNSRecord(got, tc.base, tc.ssh); again != got || changed2 {
				t.Fatalf("second pass changed %q to %q", got, again)
			}
		})
	}
}

type fakeDNSMasqStore struct {
	raw            string
	reads, writes  int
	readErr, wrErr error
}

func (f *fakeDNSMasqStore) GetNetworkConfigValue(network, key string) (string, error) {
	f.reads++
	if network != "incusbr0" || key != "raw.dnsmasq" {
		return "", errors.New("unexpected network/key " + network + "/" + key)
	}
	return f.raw, f.readErr
}

func (f *fakeDNSMasqStore) SetNetworkConfigValue(network, key, value string) error {
	f.writes++
	if network != "incusbr0" || key != "raw.dnsmasq" {
		return errors.New("unexpected network/key " + network + "/" + key)
	}
	if f.wrErr != nil {
		return f.wrErr
	}
	f.raw = value
	return nil
}

func TestCleanupBridgeDNSRecord(t *testing.T) {
	t.Run("no base domain: the bridge is not even read", func(t *testing.T) {
		f := &fakeDNSMasqStore{raw: "address=/example.com/10.0.3.5"}
		if err := cleanupBridgeDNSRecord(f, "incusbr0", "", "ssh.example.com"); err != nil {
			t.Fatal(err)
		}
		if f.reads != 0 || f.writes != 0 || f.raw != "address=/example.com/10.0.3.5" {
			t.Fatalf("reads=%d writes=%d raw=%q", f.reads, f.writes, f.raw)
		}
	})
	t.Run("nothing to remove: no write", func(t *testing.T) {
		f := &fakeDNSMasqStore{raw: "server=/corp.internal/10.1.1.1"}
		if err := cleanupBridgeDNSRecord(f, "incusbr0", "example.com", ""); err != nil {
			t.Fatal(err)
		}
		if f.writes != 0 {
			t.Fatalf("writes=%d, want 0", f.writes)
		}
	})
	t.Run("record removed, operator line kept", func(t *testing.T) {
		f := &fakeDNSMasqStore{raw: "address=/example.com/10.0.3.5\nserver=/ssh.example.com/#\nserver=/corp.internal/10.1.1.1"}
		if err := cleanupBridgeDNSRecord(f, "incusbr0", "example.com", "ssh.example.com"); err != nil {
			t.Fatal(err)
		}
		if f.writes != 1 || f.raw != "server=/corp.internal/10.1.1.1" {
			t.Fatalf("writes=%d raw=%q", f.writes, f.raw)
		}
		// A restart after the upgrade is a no-op.
		if err := cleanupBridgeDNSRecord(f, "incusbr0", "example.com", "ssh.example.com"); err != nil || f.writes != 1 {
			t.Fatalf("second run: err=%v writes=%d", err, f.writes)
		}
	})
	t.Run("only the record: key unset", func(t *testing.T) {
		f := &fakeDNSMasqStore{raw: "address=/example.com/10.0.3.5\nserver=/ssh.example.com/#"}
		if err := cleanupBridgeDNSRecord(f, "incusbr0", "example.com", "ssh.example.com"); err != nil {
			t.Fatal(err)
		}
		if f.writes != 1 || f.raw != "" {
			t.Fatalf("writes=%d raw=%q", f.writes, f.raw)
		}
	})
	t.Run("read and write errors are returned", func(t *testing.T) {
		if err := cleanupBridgeDNSRecord(&fakeDNSMasqStore{readErr: errors.New("boom")}, "incusbr0", "example.com", ""); err == nil {
			t.Fatal("read error swallowed")
		}
		f := &fakeDNSMasqStore{raw: "address=/example.com/10.0.3.5", wrErr: errors.New("boom")}
		if err := cleanupBridgeDNSRecord(f, "incusbr0", "example.com", ""); err == nil {
			t.Fatal("write error swallowed")
		}
	})
}
