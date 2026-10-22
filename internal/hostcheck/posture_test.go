//go:build !windows

package hostcheck

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Posture checks (#1103).
//
// The governing property throughout: **unknown must never report OK**. A
// posture check that passes when it learned nothing is worse than no
// check at all — it converts "we have no evidence" into "we verified it",
// which is the exact false assurance #1103 exists to stop. Most of the
// cases below are therefore about what happens when the evidence is
// missing or malformed, not about the happy path.

// tempPaths builds a posturePaths pointing entirely at a temp tree, so
// no assertion here depends on the machine running the tests.
func tempPaths(t *testing.T) (posturePaths, string) {
	t.Helper()
	dir := t.TempDir()
	return posturePaths{
		procMounts:       filepath.Join(dir, "mounts"),
		sysBlock:         filepath.Join(dir, "sys-block"),
		efiVars:          filepath.Join(dir, "efivars"),
		auditdPID:        filepath.Join(dir, "auditd.pid"),
		sshdConfig:       filepath.Join(dir, "sshd_config"),
		sshdConfigDir:    filepath.Join(dir, "sshd_config.d"),
		aptPeriodic:      filepath.Join(dir, "20auto-upgrades"),
		tunnelUnit:       filepath.Join(dir, "containarium-tunnel.service"),
		tunnelUnitDropIn: filepath.Join(dir, "containarium-tunnel.service.d"),
		incusDataDir:     "/var/lib/incus",
		// Default to "blocked", the desirable state, so a test that isn't
		// about the metadata check doesn't accidentally depend on the
		// network of the machine running it.
		metadataDialer: func() error { return errors.New("no route to host") },
		imdsBlockUnit:  filepath.Join(dir, "containarium-imds-block.service"),
		imdsBlockWants: filepath.Join(dir, "multi-user.target.wants", "containarium-imds-block.service"),
		// No iptables to ask: unknown, which must not pass.
		metadataBlockProbe: func() (bool, string, error) { return false, "", errors.New("iptables: command not found") },
	}, dir
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// TestRunPosture_AllChecksAreNonBlocking is the contract that keeps this
// PR from making the product decision #1103 reserves (fix 5). If a
// posture check ever became Required, a hardening warning would start
// failing `doctor` and flipping the cloud's self_check_ok — silently
// gating enrollment on a decision nobody made.
func TestRunPosture_AllChecksAreNonBlocking(t *testing.T) {
	p, _ := tempPaths(t)
	checks := runPosture(p)

	if len(checks) == 0 {
		t.Fatal("runPosture returned no checks")
	}
	for _, c := range checks {
		if c.Required {
			t.Errorf("posture check %q is Required — posture must not gate capability (#1103 fix 5 is an open product decision)", c.Name)
		}
		if c.Kind != KindPosture {
			t.Errorf("check %q has Kind %q, want %q", c.Name, c.Kind, KindPosture)
		}
	}
	// The load-bearing consequence, asserted directly rather than implied.
	if !AllRequiredPass(checks) {
		t.Error("AllRequiredPass must stay true over posture checks alone, whatever their results")
	}
}

// TestRunPosture_UnknownHostReportsNoPasses: given a temp tree with no
// evidence in it at all, nothing may claim to have verified anything.
// The metadata check is the sole exception — an unreachable endpoint IS
// the positive evidence there.
func TestRunPosture_UnknownHostReportsNoPasses(t *testing.T) {
	p, _ := tempPaths(t)
	for _, c := range runPosture(p) {
		if c.Name == "cloud metadata endpoint blocked" {
			if !c.OK {
				t.Errorf("unreachable metadata endpoint should be OK, got not-OK: %s", c.Detail)
			}
			continue
		}
		if c.OK {
			t.Errorf("check %q reported OK with no evidence available: %s", c.Name, c.Detail)
		}
		if !strings.Contains(c.Detail, "could not determine") && c.Detail == "" {
			t.Errorf("check %q failed without saying why", c.Name)
		}
	}
}

func TestDeviceForPath(t *testing.T) {
	const mounts = `sysfs /sys sysfs rw 0 0
/dev/sda1 / ext4 rw 0 0
tmpfs /run tmpfs rw 0 0
/dev/mapper/cryptdata /var/lib/incus ext4 rw 0 0
/dev/sdb1 /var/lib/incus/deep/nested ext4 rw 0 0
`
	tests := []struct {
		name, target, wantDev, wantMP string
	}{
		// The whole reason for longest-prefix: "/" also matches, and a
		// first-match implementation would inspect the wrong volume and
		// report the root disk's encryption state as the data disk's.
		{"longest prefix wins", "/var/lib/incus", "/dev/mapper/cryptdata", "/var/lib/incus"},
		{"falls back to root", "/opt/containarium", "/dev/sda1", "/"},
		{"exact deeper mount", "/var/lib/incus/deep/nested", "/dev/sdb1", "/var/lib/incus/deep/nested"},
		// A mount point that is a string prefix but not a PATH prefix
		// must not match: /var/lib/incusdata is not inside /var/lib/incus.
		{"not a path-component prefix", "/var/lib/incusdata", "/dev/sda1", "/"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dev, mp := deviceForPath(mounts, tc.target)
			if dev != tc.wantDev || mp != tc.wantMP {
				t.Errorf("deviceForPath(%q) = (%q, %q), want (%q, %q)", tc.target, dev, mp, tc.wantDev, tc.wantMP)
			}
		})
	}
}

func TestDiskEncryptionCheck(t *testing.T) {
	// /sys/block is keyed by the kernel name, so this is the shape a real
	// host presents once the mapper alias has been resolved.
	t.Run("dm-crypt passes", func(t *testing.T) {
		p, _ := tempPaths(t)
		write(t, p.procMounts, "/dev/dm-0 /var/lib/incus ext4 rw 0 0\n")
		write(t, filepath.Join(p.sysBlock, "dm-0/dm/uuid"), "CRYPT-LUKS2-abc123-cryptdata\n")

		c := diskEncryptionCheck(p)
		if !c.OK {
			t.Errorf("dm-crypt volume should pass: %s", c.Detail)
		}
	})

	t.Run("plain partition fails and explains CMEK is unobservable", func(t *testing.T) {
		p, _ := tempPaths(t)
		write(t, p.procMounts, "/dev/sda1 /var/lib/incus ext4 rw 0 0\n")

		c := diskEncryptionCheck(p)
		if c.OK {
			t.Error("a plain partition must not pass as encrypted")
		}
		// The nuance is the point: on a cloud BYOC host the disk very
		// likely IS encrypted at rest by the provider, invisibly. Without
		// this the check reads as "the customer's disk is plaintext",
		// which we do not know and should not imply.
		if !strings.Contains(c.Detail, "cannot be observed from inside the guest") {
			t.Errorf("detail must not imply the disk is plaintext when provider encryption is merely unobservable: %q", c.Detail)
		}
	})

	t.Run("non-crypt device-mapper fails", func(t *testing.T) {
		p, _ := tempPaths(t)
		write(t, p.procMounts, "/dev/dm-1 /var/lib/incus ext4 rw 0 0\n")
		write(t, filepath.Join(p.sysBlock, "dm-1/dm/uuid"), "LVM-xyz\n")

		if c := diskEncryptionCheck(p); c.OK {
			t.Errorf("plain LVM must not pass as encrypted: %s", c.Detail)
		}
	})

	t.Run("unreadable mounts is unknown not pass", func(t *testing.T) {
		p, _ := tempPaths(t) // procMounts never created
		c := diskEncryptionCheck(p)
		if c.OK {
			t.Error("must not pass when /proc/mounts is unreadable")
		}
		if !strings.Contains(c.Detail, "could not determine") {
			t.Errorf("detail should mark this unknown, got %q", c.Detail)
		}
	})
}

func TestParseSecureBootVar(t *testing.T) {
	tests := []struct {
		name        string
		raw         []byte
		wantEnabled bool
		wantOK      bool
	}{
		{"enabled", []byte{6, 0, 0, 0, 1}, true, true},
		{"disabled", []byte{6, 0, 0, 0, 0}, false, true},
		{"short", []byte{6, 0, 0, 0}, false, false},
		{"empty", nil, false, false},
		{"too long", []byte{6, 0, 0, 0, 1, 1}, false, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			enabled, ok := parseSecureBootVar(tc.raw)
			if enabled != tc.wantEnabled || ok != tc.wantOK {
				t.Errorf("= (%v, %v), want (%v, %v)", enabled, ok, tc.wantEnabled, tc.wantOK)
			}
		})
	}
}

func TestSecureBootCheck(t *testing.T) {
	t.Run("enabled passes", func(t *testing.T) {
		p, _ := tempPaths(t)
		write(t, filepath.Join(p.efiVars, "SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"), "")
		if err := os.WriteFile(filepath.Join(p.efiVars, "SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"),
			[]byte{6, 0, 0, 0, 1}, 0o600); err != nil {
			t.Fatal(err)
		}
		if c := secureBootCheck(p); !c.OK {
			t.Errorf("SecureBoot=1 should pass: %s", c.Detail)
		}
	})

	t.Run("no efivars is a definite negative", func(t *testing.T) {
		p, _ := tempPaths(t)
		c := secureBootCheck(p)
		if c.OK {
			t.Error("legacy BIOS must not pass")
		}
		// Not "could not determine": no EFI genuinely means no measured
		// boot is possible. Reporting it as unknown would understate it.
		if !strings.Contains(c.Detail, "legacy BIOS") {
			t.Errorf("detail should name legacy BIOS as the finding, got %q", c.Detail)
		}
	})

	t.Run("efivars without the variable is unknown", func(t *testing.T) {
		p, _ := tempPaths(t)
		if err := os.MkdirAll(p.efiVars, 0o755); err != nil {
			t.Fatal(err)
		}
		c := secureBootCheck(p)
		if c.OK || !strings.Contains(c.Detail, "could not determine") {
			t.Errorf("EFI present but no SecureBoot var should be unknown, got OK=%v %q", c.OK, c.Detail)
		}
	})
}

func TestAuditdCheck(t *testing.T) {
	t.Run("pidfile present passes", func(t *testing.T) {
		p, _ := tempPaths(t)
		write(t, p.auditdPID, "1234\n")
		if c := auditdCheck(p); !c.OK {
			t.Errorf("auditd pidfile should pass: %s", c.Detail)
		}
	})
	t.Run("absent fails", func(t *testing.T) {
		p, _ := tempPaths(t)
		if c := auditdCheck(p); c.OK {
			t.Error("missing pidfile must not pass")
		}
	})
	t.Run("empty pidfile is unknown", func(t *testing.T) {
		p, _ := tempPaths(t)
		write(t, p.auditdPID, "  \n")
		c := auditdCheck(p)
		if c.OK || !strings.Contains(c.Detail, "could not determine") {
			t.Errorf("empty pidfile should be unknown, got OK=%v %q", c.OK, c.Detail)
		}
	})
}

func TestSSHDDirective(t *testing.T) {
	tests := []struct {
		name, config, key, def, want string
	}{
		{"absent uses default", "Port 22\n", "PasswordAuthentication", "yes", "yes"},
		{"simple", "PasswordAuthentication no\n", "PasswordAuthentication", "yes", "no"},
		{"case insensitive key", "passwordauthentication NO\n", "PasswordAuthentication", "yes", "NO"},
		{"comments ignored", "#PasswordAuthentication yes\nPasswordAuthentication no\n", "PasswordAuthentication", "yes", "no"},
		// OpenSSH takes the FIRST occurrence, not the last. A last-wins
		// implementation returns "yes" here and would report a hardened
		// host as unhardened (or worse, the reverse).
		{"first occurrence wins", "PasswordAuthentication no\nPasswordAuthentication yes\n", "PasswordAuthentication", "yes", "no"},
		// A directive inside a Match block is conditional; treating it as
		// global misreports the host-wide setting.
		{"match block ignored", "Match User bob\nPasswordAuthentication yes\n", "PasswordAuthentication", "no", "no"},
		{"directive before match still counts", "PasswordAuthentication no\nMatch User bob\nPasswordAuthentication yes\n", "PasswordAuthentication", "yes", "no"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := sshdDirective(tc.config, tc.key, tc.def); got != tc.want {
				t.Errorf("sshdDirective() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestSSHDConfigCheck(t *testing.T) {
	t.Run("hardened passes", func(t *testing.T) {
		p, _ := tempPaths(t)
		write(t, p.sshdConfig, "PermitRootLogin no\nPasswordAuthentication no\n")
		if c := sshdConfigCheck(p); !c.OK {
			t.Errorf("hardened sshd should pass: %s", c.Detail)
		}
	})

	t.Run("password auth on fails even with root login off", func(t *testing.T) {
		p, _ := tempPaths(t)
		write(t, p.sshdConfig, "PermitRootLogin no\nPasswordAuthentication yes\n")
		c := sshdConfigCheck(p)
		if c.OK {
			t.Error("password auth enabled must fail regardless of root login")
		}
		if !strings.Contains(c.Detail, "PasswordAuthentication") {
			t.Errorf("detail should name the offending directive, got %q", c.Detail)
		}
	})

	t.Run("default password auth is yes so a bare config fails", func(t *testing.T) {
		p, _ := tempPaths(t)
		write(t, p.sshdConfig, "Port 22\n")
		if c := sshdConfigCheck(p); c.OK {
			t.Error("an sshd_config that sets nothing inherits PasswordAuthentication=yes and must fail")
		}
	})

	// Modern distros ship `Include /etc/ssh/sshd_config.d/*.conf` at the
	// TOP of sshd_config, so with first-match-wins a drop-in OVERRIDES the
	// main file. Reading them in the wrong order reports the overridden
	// value — on a cloud image, usually the insecure one.
	t.Run("drop-in overrides the main file", func(t *testing.T) {
		p, _ := tempPaths(t)
		write(t, p.sshdConfig, "PasswordAuthentication yes\nPermitRootLogin yes\n")
		write(t, filepath.Join(p.sshdConfigDir, "60-hardening.conf"), "PasswordAuthentication no\nPermitRootLogin no\n")

		if c := sshdConfigCheck(p); !c.OK {
			t.Errorf("drop-in hardening must override the main file: %s", c.Detail)
		}
	})

	t.Run("drop-ins apply in lexical order", func(t *testing.T) {
		p, _ := tempPaths(t)
		write(t, p.sshdConfig, "Port 22\n")
		write(t, filepath.Join(p.sshdConfigDir, "10-first.conf"), "PasswordAuthentication no\nPermitRootLogin no\n")
		write(t, filepath.Join(p.sshdConfigDir, "90-later.conf"), "PasswordAuthentication yes\n")

		if c := sshdConfigCheck(p); !c.OK {
			t.Errorf("the lexically-first drop-in wins under first-match-wins: %s", c.Detail)
		}
	})

	t.Run("missing config is unknown not pass", func(t *testing.T) {
		p, _ := tempPaths(t)
		c := sshdConfigCheck(p)
		if c.OK || !strings.Contains(c.Detail, "could not determine") {
			t.Errorf("missing sshd_config should be unknown, got OK=%v %q", c.OK, c.Detail)
		}
	})
}

func TestTunnelTokenExposedCheck(t *testing.T) {
	t.Run("missing unit is unknown not pass", func(t *testing.T) {
		p, _ := tempPaths(t)
		c := tunnelTokenExposedCheck(p)
		if c.OK || !strings.Contains(c.Detail, "could not determine") {
			t.Errorf("missing tunnel unit should be unknown, got OK=%v %q", c.OK, c.Detail)
		}
	})

	t.Run("stale pre-#965 unit with --token on ExecStart fails", func(t *testing.T) {
		p, _ := tempPaths(t)
		write(t, p.tunnelUnit, "[Unit]\nDescription=Containarium Tunnel Client\n\n"+
			"[Service]\nType=simple\n"+
			"ExecStart=/usr/local/bin/containarium tunnel --sentinel-addr asia-east1.containarium.dev:443 "+
			"--token abc123scopedtoken --spot-id fts-13700k --ports 22,8080,443 --pool fts\n"+
			"Restart=always\n")
		c := tunnelTokenExposedCheck(p)
		if c.OK {
			t.Error("--token on the ExecStart line must fail this check")
		}
		if !strings.Contains(c.Detail, "--token") {
			t.Errorf("detail should name what was found, got %q", c.Detail)
		}
		if strings.Contains(c.Detail, "abc123scopedtoken") {
			t.Errorf("detail must not echo the token value itself, got %q", c.Detail)
		}
	})

	t.Run("current EnvironmentFile form passes, continuation lines included", func(t *testing.T) {
		p, _ := tempPaths(t)
		// Mirrors internal/cmd.renderTunnelUnit's actual output shape (#965):
		// the token lives in EnvironmentFile=, never on ExecStart.
		write(t, p.tunnelUnit, "[Unit]\nDescription=Containarium Tunnel Client (fts pool)\n\n"+
			"[Service]\nType=simple\n"+
			"EnvironmentFile=/etc/containarium/tunnel-token.env\n"+
			"ExecStart=/usr/local/bin/containarium tunnel \\\n"+
			"  --sentinel-addr asia-east1.containarium.dev:443 \\\n"+
			"  --spot-id fts-13700k \\\n"+
			"  --ports 22,8080,443 \\\n"+
			"  --pool fts\n"+
			"Restart=always\n")
		c := tunnelTokenExposedCheck(p)
		if !c.OK {
			t.Errorf("EnvironmentFile= form must pass: %s", c.Detail)
		}
	})

	t.Run("unit with no ExecStart line is unknown not pass", func(t *testing.T) {
		p, _ := tempPaths(t)
		write(t, p.tunnelUnit, "[Unit]\nDescription=broken unit\n")
		c := tunnelTokenExposedCheck(p)
		if c.OK || !strings.Contains(c.Detail, "could not determine") {
			t.Errorf("no ExecStart= should be unknown, got OK=%v %q", c.OK, c.Detail)
		}
	})

	// The CodeRabbit follow-up on cloud#1074: a check that reads only the
	// base unit file can be defeated by a drop-in overriding ExecStart=.
	t.Run("drop-in overriding ExecStart with --token fails even though the base file is safe", func(t *testing.T) {
		p, _ := tempPaths(t)
		write(t, p.tunnelUnit, "[Unit]\nDescription=Containarium Tunnel Client\n\n"+
			"[Service]\nType=simple\n"+
			"EnvironmentFile=/etc/containarium/tunnel-token.env\n"+
			"ExecStart=/usr/local/bin/containarium tunnel --spot-id fts-13700k --pool fts\n"+
			"Restart=always\n")
		write(t, filepath.Join(p.tunnelUnitDropIn, "10-override.conf"),
			"[Service]\nExecStart=\n"+
				"ExecStart=/usr/local/bin/containarium tunnel --token abc123scopedtoken --spot-id fts-13700k --pool fts\n")

		c := tunnelTokenExposedCheck(p)
		if c.OK {
			t.Error("a drop-in overriding ExecStart with --token must fail this check even though the base file is safe")
		}
		if !strings.Contains(c.Detail, "--token") {
			t.Errorf("detail should name what was found, got %q", c.Detail)
		}
	})

	t.Run("drop-in overriding ExecStart with the safe form passes", func(t *testing.T) {
		p, _ := tempPaths(t)
		// Base file is deliberately the STALE/unsafe pattern; the drop-in
		// (lexically after it, systemd's own override order) replaces it
		// with the safe EnvironmentFile= form — the effective command must
		// be judged by what actually runs, not by the base file alone.
		write(t, p.tunnelUnit, "[Unit]\nDescription=Containarium Tunnel Client\n\n"+
			"[Service]\nType=simple\n"+
			"ExecStart=/usr/local/bin/containarium tunnel --token abc123scopedtoken --spot-id fts-13700k --pool fts\n"+
			"Restart=always\n")
		write(t, filepath.Join(p.tunnelUnitDropIn, "10-override.conf"),
			"[Service]\nExecStart=\n"+
				"ExecStart=/usr/local/bin/containarium tunnel --spot-id fts-13700k --pool fts\n")

		c := tunnelTokenExposedCheck(p)
		if !c.OK {
			t.Errorf("a drop-in replacing the stale base ExecStart with the safe form must pass: %s", c.Detail)
		}
	})

	t.Run("drop-in with no ExecStart directive leaves the base file's value in effect", func(t *testing.T) {
		p, _ := tempPaths(t)
		write(t, p.tunnelUnit, "[Unit]\nDescription=Containarium Tunnel Client\n\n"+
			"[Service]\nType=simple\n"+
			"ExecStart=/usr/local/bin/containarium tunnel --token abc123scopedtoken --spot-id fts-13700k --pool fts\n"+
			"Restart=always\n")
		write(t, filepath.Join(p.tunnelUnitDropIn, "10-unrelated.conf"), "[Service]\nRestart=on-failure\n")

		c := tunnelTokenExposedCheck(p)
		if c.OK {
			t.Error("a drop-in with no ExecStart= directive must not mask the base file's --token")
		}
	})

	t.Run("multiple drop-ins apply in lexical order, later wins", func(t *testing.T) {
		p, _ := tempPaths(t)
		write(t, p.tunnelUnit, "[Unit]\nDescription=Containarium Tunnel Client\n\n"+
			"[Service]\nType=simple\n"+
			"ExecStart=/usr/local/bin/containarium tunnel --spot-id fts-13700k --pool fts\n"+
			"Restart=always\n")
		write(t, filepath.Join(p.tunnelUnitDropIn, "10-first.conf"),
			"[Service]\nExecStart=\nExecStart=/usr/local/bin/containarium tunnel --token abc123scopedtoken --pool fts\n")
		write(t, filepath.Join(p.tunnelUnitDropIn, "90-later.conf"),
			"[Service]\nExecStart=\nExecStart=/usr/local/bin/containarium tunnel --spot-id fts-13700k --pool fts\n")

		c := tunnelTokenExposedCheck(p)
		if !c.OK {
			t.Errorf("the lexically-last drop-in must win: %s", c.Detail)
		}
	})
}

func TestExtractExecStart(t *testing.T) {
	tests := []struct {
		name, unit, want string
	}{
		{
			name: "single line",
			unit: "[Service]\nExecStart=/usr/local/bin/containarium tunnel --token x\nRestart=always\n",
			want: "ExecStart=/usr/local/bin/containarium tunnel --token x",
		},
		{
			name: "continuation lines joined",
			unit: "ExecStart=/usr/local/bin/containarium tunnel \\\n--spot-id x \\\npool fts\nRestart=always\n",
			want: "ExecStart=/usr/local/bin/containarium tunnel  --spot-id x  pool fts",
		},
		{
			name: "absent",
			unit: "[Unit]\nDescription=x\n",
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := extractExecStart(tt.unit); got != tt.want {
				t.Errorf("extractExecStart() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestAptPeriodicEnabled(t *testing.T) {
	tests := []struct {
		name, config string
		want         bool
	}{
		{"enabled", `APT::Periodic::Unattended-Upgrade "1";`, true},
		{"disabled", `APT::Periodic::Unattended-Upgrade "0";`, false},
		{"absent", `APT::Periodic::Update-Package-Lists "1";`, false},
		// APT reads the value as a day interval, so "7" is enabled-weekly.
		// Treating only "1" as on would misreport a configured host.
		{"weekly interval counts as enabled", `APT::Periodic::Unattended-Upgrade "7";`, true},
		{"comment ignored", "// APT::Periodic::Unattended-Upgrade \"1\";", false},
		{"empty value", `APT::Periodic::Unattended-Upgrade "";`, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := aptPeriodicEnabled(tc.config, "Unattended-Upgrade"); got != tc.want {
				t.Errorf("aptPeriodicEnabled(%q) = %v, want %v", tc.config, got, tc.want)
			}
		})
	}
}

func TestUnattendedUpgradesCheck_MissingFileIsUnknown(t *testing.T) {
	p, _ := tempPaths(t)
	c := unattendedUpgradesCheck(p)
	if c.OK {
		t.Error("must not pass with no APT config")
	}
	// Non-Debian hosts have a different mechanism entirely, so absence is
	// genuinely unknown rather than a failure to configure.
	if !strings.Contains(c.Detail, "could not determine") {
		t.Errorf("absence on a non-Debian host is unknown, got %q", c.Detail)
	}
}

func TestMetadataReachableCheck(t *testing.T) {
	// OK means UNREACHABLE here — the desirable state is the connection
	// failing. Worth an explicit test because the polarity is easy to
	// invert and the inverted version looks perfectly reasonable.
	t.Run("unreachable is the pass", func(t *testing.T) {
		p, _ := tempPaths(t)
		p.metadataDialer = func() error { return errors.New("connect: no route to host") }
		c := metadataReachableCheck(p)
		if !c.OK {
			t.Errorf("a blocked metadata endpoint is the desired state: %s", c.Detail)
		}
	})

	t.Run("reachable is the failure", func(t *testing.T) {
		p, _ := tempPaths(t)
		p.metadataDialer = func() error { return nil }
		c := metadataReachableCheck(p)
		if c.OK {
			t.Error("a reachable metadata endpoint must not pass")
		}
		if !strings.Contains(c.Detail, "instance credentials") {
			t.Errorf("detail should state the consequence, got %q", c.Detail)
		}
	})
}

// TestMetadataBlockCheck covers #2298: a host whose metadata-endpoint block
// is missing — rule not in the kernel, or no enabled boot unit to re-apply
// it — must fail the posture item and say how to fix it.
func TestMetadataBlockCheck(t *testing.T) {
	const rule = "iptables -A FORWARD -s 10.0.3.1/24 -d 169.254.169.254 -j DROP"
	present := func() (bool, string, error) { return true, "present: " + rule, nil }
	absent := func() (bool, string, error) { return false, "absent: " + rule, nil }
	unknown := func() (bool, string, error) { return false, "", errors.New("exit status 4: Permission denied") }

	cases := []struct {
		name       string
		probe      func() (bool, string, error)
		unit       bool // unit file installed
		enabled    bool // multi-user.target.wants symlink present
		wantOK     bool
		wantDetail []string
	}{
		{name: "rule present and boot unit enabled passes", probe: present, unit: true, enabled: true, wantOK: true},
		{name: "rule absent fails with the remediation", probe: absent, unit: true, enabled: true,
			wantDetail: []string{"not in the kernel", "containarium hostharden block-metadata --persist incusbr0"}},
		{name: "boot unit missing fails: the rule will not survive a reboot", probe: present,
			wantDetail: []string{"not installed", "reboot", "block-metadata --persist"}},
		{name: "boot unit installed but not enabled fails", probe: present, unit: true,
			wantDetail: []string{"not enabled", "reboot", "block-metadata --persist"}},
		{name: "nothing in place reports both halves", probe: absent,
			wantDetail: []string{"not in the kernel", "not installed"}},
		{name: "probe cannot tell is unknown, never a pass", probe: unknown, unit: true, enabled: true,
			wantDetail: []string{"could not determine", "Permission denied"}},
		{name: "no probe is unknown", unit: true, enabled: true,
			wantDetail: []string{"could not determine"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, _ := tempPaths(t)
			p.metadataBlockProbe = tc.probe
			if tc.unit {
				write(t, p.imdsBlockUnit, "[Unit]\n")
			}
			if tc.enabled {
				if err := os.MkdirAll(filepath.Dir(p.imdsBlockWants), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(p.imdsBlockUnit, p.imdsBlockWants); err != nil {
					t.Fatal(err)
				}
			}
			c := metadataBlockCheck(p)
			if c.OK != tc.wantOK {
				t.Fatalf("OK = %v, want %v: %s", c.OK, tc.wantOK, c.Detail)
			}
			for _, want := range tc.wantDetail {
				if !strings.Contains(c.Detail, want) {
					t.Errorf("detail %q does not mention %q", c.Detail, want)
				}
			}
		})
	}
}

// TestRunPosture_IncludesMetadataBlock: the item is wired into the posture
// list, not only defined.
func TestRunPosture_IncludesMetadataBlock(t *testing.T) {
	p, _ := tempPaths(t)
	p.metadataBlockProbe = func() (bool, string, error) { return false, "absent", nil }
	for _, c := range runPosture(p) {
		if c.Name == metadataBlockCheck(p).Name {
			if c.OK {
				t.Errorf("posture reports the missing block as OK: %s", c.Detail)
			}
			return
		}
	}
	t.Error("runPosture does not include the metadata-endpoint block check")
}

func TestWireName(t *testing.T) {
	// The two groups must stay distinguishable across a wire format that
	// carries only {name, ok, detail} — otherwise the cloud cannot tell a
	// hardening warning from a capability failure, which is the exact
	// conflation #1103 is about.
	posture := Check{Name: "auditd running", Kind: KindPosture}
	if got, want := posture.WireName(), "posture: auditd running"; got != want {
		t.Errorf("posture WireName = %q, want %q", got, want)
	}
	capability := Check{Name: "incus binary present", Kind: KindCapability}
	if got, want := capability.WireName(), "incus binary present"; got != want {
		t.Errorf("capability WireName = %q, want %q", got, want)
	}
	// Zero value must read as capability so every pre-existing Check
	// construction keeps its meaning.
	if got, want := (Check{Name: "x"}).WireName(), "x"; got != want {
		t.Errorf("zero-Kind WireName = %q, want %q", got, want)
	}
}

// TestRun_UnchangedByPosture: Run() must keep returning capability checks
// only. If posture ever leaks into it, AllRequiredPass starts mixing a
// hardening verdict into a liveness verdict and container creation gets
// gated on a decision nobody made.
func TestRun_UnchangedByPosture(t *testing.T) {
	for _, c := range Run() {
		if c.Kind == KindPosture {
			t.Errorf("Run() returned posture check %q — posture belongs to RunPosture()", c.Name)
		}
	}
}

// TestResolveDMName is the regression test for the real-host bug that the
// security scanner's taint warning led to. /proc/mounts carries the
// device-mapper ALIAS (/dev/mapper/cryptdata), a symlink to the kernel name
// (/dev/dm-0), and /sys/block only knows the latter. Without resolution every
// LUKS host reported "not dm-crypt" — a false negative on precisely the hosts
// that are encrypted.
//
// Driven directly rather than through diskEncryptionCheck because
// deviceForPath only accepts /dev/-prefixed devices, and a test cannot create
// symlinks under the real /dev.
func TestResolveDMName(t *testing.T) {
	dir := t.TempDir()
	kernelDev := filepath.Join(dir, "dm-0")
	aliasDir := filepath.Join(dir, "mapper")
	aliasDev := filepath.Join(aliasDir, "cryptdata")
	write(t, kernelDev, "")
	if err := os.MkdirAll(aliasDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(kernelDev, aliasDev); err != nil {
		t.Fatal(err)
	}

	if got, want := resolveDMName(aliasDev), "dm-0"; got != want {
		t.Errorf("resolveDMName(mapper alias) = %q, want %q — /sys/block is keyed by the kernel name", got, want)
	}
	if got, want := resolveDMName(kernelDev), "dm-0"; got != want {
		t.Errorf("resolveDMName(kernel name) = %q, want %q", got, want)
	}
	// Unresolvable path: no panic, no traversal, just the last segment.
	if got, want := resolveDMName("/dev/does-not-exist"), "does-not-exist"; got != want {
		t.Errorf("resolveDMName(missing) = %q, want %q", got, want)
	}
	// Traversal attempt is bounded to one segment.
	if got := resolveDMName("/dev/../../etc/passwd"); strings.Contains(got, "/") {
		t.Errorf("resolveDMName must return a single path segment, got %q", got)
	}
}
