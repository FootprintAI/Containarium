//go:build !windows

package hostcheck

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Host security-posture checks (#1103).
//
// The capability checks in run.go answer "can this host run workloads".
// These answer "is it safe to run them here" — a different question that
// for enterprise BYOC is the load-bearing one, because the machine is
// supplied by the customer, in the customer's account, from an image we
// did not build.
//
// Three rules govern everything in this file:
//
//  1. **Unknown is never OK.** A check that cannot measure its property
//     reports NOT-OK with a "could not determine" detail. The whole
//     premise of #1103 is that we cannot evidence a dedication claim, so
//     a check that silently passes when it learned nothing would
//     manufacture exactly the false assurance being complained about.
//     The practical effect — an ordinary unhardened host lights up with
//     warnings — is the finding, not a defect.
//
//  2. **Non-blocking.** Every posture check is Required=false, so
//     AllRequiredPass (and therefore the cloud's self_check_ok, and
//     `doctor`'s exit code) is unchanged. Whether a posture miss should
//     block enrollment is a product decision (#1103 fix 5) that this
//     code deliberately leaves open.
//
//  3. **Say what was measured, not what was hoped.** Details name the
//     evidence — the file read, the value found — so a reviewer can
//     re-derive the verdict by hand. "Not encrypted" and "could not tell
//     whether it is encrypted" are different claims and are reported
//     differently.

// posturePaths are the host files the posture checks read. Grouped into
// a struct so tests can point every check at a temp tree instead of the
// real host — a posture check that can only be tested on a correctly
// hardened machine is a posture check nobody will ever run red.
type posturePaths struct {
	procMounts     string // /proc/mounts
	sysBlock       string // /sys/block
	efiVars        string // /sys/firmware/efi/efivars
	auditdPID      string // /run/auditd.pid
	sshdConfig     string // /etc/ssh/sshd_config
	sshdConfigDir  string // /etc/ssh/sshd_config.d
	aptPeriodic    string // /etc/apt/apt.conf.d/20auto-upgrades
	incusDataDir   string // /var/lib/incus — the volume that holds tenant data
	recoveryDir    string // /mnt/incus-data — where containarium-recovery.yaml is written (#1154)
	metadataDialer func() error
}

func defaultPosturePaths() posturePaths {
	return posturePaths{
		procMounts:     "/proc/mounts",
		sysBlock:       "/sys/block",
		efiVars:        "/sys/firmware/efi/efivars",
		auditdPID:      "/run/auditd.pid",
		sshdConfig:     "/etc/ssh/sshd_config",
		sshdConfigDir:  "/etc/ssh/sshd_config.d",
		aptPeriodic:    "/etc/apt/apt.conf.d/20auto-upgrades",
		incusDataDir:   "/var/lib/incus",
		recoveryDir:    DefaultRecoveryDir,
		metadataDialer: dialMetadataServer,
	}
}

// RunPosture executes every host security-posture check.
//
// Separate from Run() rather than appended to it, deliberately: Run()'s
// result feeds AllRequiredPass, which drives the cloud's self_check_ok
// and the daemon's startup self-check. Folding posture into it would
// couple a hardening verdict to a liveness verdict, and any later change
// to a posture check's Required flag would silently start gating
// container creation.
func RunPosture() []Check {
	return runPosture(defaultPosturePaths())
}

func runPosture(p posturePaths) []Check {
	checks := []Check{
		diskEncryptionCheck(p),
		secureBootCheck(p),
		auditdCheck(p),
		sshdConfigCheck(p),
		unattendedUpgradesCheck(p),
		metadataReachableCheck(p),
		recoveryConfigDurableCheck(p),
	}
	for i := range checks {
		checks[i].Kind = KindPosture
		checks[i].Required = false
	}
	return checks
}

// --- disk encryption -------------------------------------------------

// diskEncryptionCheck reports whether the volume holding tenant data is
// backed by a dm-crypt device.
//
// Deliberately narrow about what a pass means. Guest-visible dm-crypt is
// the only encryption this host can PROVE; provider-managed at-rest
// encryption (GCP CMEK/CSEK, EBS encryption) is invisible from inside
// the guest, so its absence here is "not observable", not "absent". The
// detail says so, because on a cloud BYOC host that is the likely case
// and a reviewer must not read this as "the customer's disk is
// plaintext".
func diskEncryptionCheck(p posturePaths) Check {
	c := Check{Name: "data volume encrypted (dm-crypt)"}

	mounts, err := os.ReadFile(p.procMounts) // #nosec G304 -- package-owned constant (/proc/mounts), overridden only by tests
	if err != nil {
		c.Detail = fmt.Sprintf("could not determine: reading %s: %v", p.procMounts, err)
		return c
	}
	dev, mountPoint := deviceForPath(string(mounts), p.incusDataDir)
	if dev == "" {
		c.Detail = fmt.Sprintf("could not determine: no mount in %s covers %s", p.procMounts, p.incusDataDir)
		return c
	}

	dmName := resolveDMName(dev)
	uuid, err := os.ReadFile(filepath.Join(p.sysBlock, dmName, "dm", "uuid")) // #nosec G304,G703 -- resolveDMName Base()-bounds dmName to a single path segment so no traversal is reachable; gosec cannot see that through the call. sysBlock is a package-owned constant.
	if err != nil {
		// Not a device-mapper device at all — a plain partition. That is a
		// definite negative for guest-visible encryption, not an unknown.
		c.Detail = fmt.Sprintf("%s (mounted at %s) is not a dm-crypt device; "+
			"provider-managed encryption (e.g. CMEK) cannot be observed from inside the guest and is neither confirmed nor ruled out",
			dev, mountPoint)
		return c
	}
	if !strings.HasPrefix(strings.TrimSpace(string(uuid)), "CRYPT-") {
		c.Detail = fmt.Sprintf("%s is device-mapper but not dm-crypt (uuid %q)", dev, strings.TrimSpace(string(uuid)))
		return c
	}
	c.OK = true
	c.Detail = fmt.Sprintf("%s backing %s is dm-crypt", dev, mountPoint)
	return c
}

// deviceForPath finds the device whose mount point is the longest prefix
// of target — i.e. the filesystem that actually holds it. Longest-prefix
// matters: with both "/" and "/var/lib/incus" mounted, the naive first
// match is "/" and the check would inspect the wrong volume.
func deviceForPath(procMounts, target string) (device, mountPoint string) {
	best := -1
	for _, line := range strings.Split(procMounts, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		dev, mp := f[0], f[1]
		if !strings.HasPrefix(dev, "/dev/") {
			continue // tmpfs, proc, cgroup…
		}
		if mp != "/" && !strings.HasPrefix(target, strings.TrimSuffix(mp, "/")+"/") && target != mp {
			continue
		}
		if len(mp) > best {
			best, device, mountPoint = len(mp), dev, mp
		}
	}
	return device, mountPoint
}

// resolveDMName maps a device path from /proc/mounts to the name
// /sys/block is keyed by.
//
// Not cosmetic. /sys/block uses the KERNEL name (dm-0), while /proc/mounts
// usually carries the device-mapper ALIAS (/dev/mapper/cryptdata), a symlink
// to it. Without resolving, /sys/block/mapper/cryptdata does not exist and
// every LUKS host reports "not dm-crypt" — a false negative on exactly the
// hosts that ARE encrypted, which is the worst direction for this check to be
// wrong in. Best-effort: an unresolvable path falls through to Base and simply
// misses, i.e. no worse than not trying.
//
// Base() also bounds the result to a single path segment, so a hostile
// /proc/mounts line cannot traverse out of the sysBlock root. /proc/mounts is
// kernel-owned so that is defence in depth, but this runs as root and the
// bound is one call.
func resolveDMName(dev string) string {
	resolved := dev
	if r, err := filepath.EvalSymlinks(dev); err == nil {
		resolved = r
	}
	return filepath.Base(resolved)
}

// --- secure boot -----------------------------------------------------

// secureBootCheck reads the EFI SecureBoot variable. Absence of the
// efivars tree at all means legacy BIOS boot, which is a definite
// negative: there is no measured-boot capability to enable.
func secureBootCheck(p posturePaths) Check {
	c := Check{Name: "secure boot enabled"}

	entries, err := os.ReadDir(p.efiVars)
	if err != nil {
		c.Detail = "not an EFI system (no efivars): legacy BIOS boot has no measured-boot capability"
		return c
	}
	// The variable is SecureBoot-<vendor-guid>; the guid is not fixed.
	var name string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "SecureBoot-") {
			name = e.Name()
			break
		}
	}
	if name == "" {
		c.Detail = "could not determine: no SecureBoot-* efivar present"
		return c
	}
	// Base() bounds the ReadDir-derived name to one segment.
	raw, err := os.ReadFile(filepath.Join(p.efiVars, filepath.Base(name))) // #nosec G304 -- efiVars is a package-owned constant; name is Base()-bounded
	if err != nil {
		c.Detail = fmt.Sprintf("could not determine: reading %s: %v", name, err)
		return c
	}
	on, ok := parseSecureBootVar(raw)
	if !ok {
		c.Detail = fmt.Sprintf("could not determine: %s is %d bytes, want 5", name, len(raw))
		return c
	}
	if !on {
		c.Detail = "SecureBoot efivar is 0 (disabled)"
		return c
	}
	c.OK = true
	c.Detail = "SecureBoot efivar is 1"
	return c
}

// parseSecureBootVar decodes an efivars blob: 4 bytes of attributes
// followed by the value. ok=false if it isn't that shape.
func parseSecureBootVar(raw []byte) (enabled, ok bool) {
	if len(raw) != 5 {
		return false, false
	}
	return raw[4] == 1, true
}

// --- auditd ----------------------------------------------------------

// auditdCheck looks for auditd's pidfile. Pidfile rather than shelling
// out to systemctl: the daemon may run where systemd isn't reachable,
// and a missing systemctl would report as "unknown" on a host that is
// in fact running auditd.
func auditdCheck(p posturePaths) Check {
	c := Check{Name: "auditd running"}
	data, err := os.ReadFile(p.auditdPID) // #nosec G304 -- package-owned constant (/run/auditd.pid), overridden only by tests
	if err != nil {
		if os.IsNotExist(err) {
			c.Detail = "no " + p.auditdPID + ": auditd is not running, so host-level audit trail is absent"
			return c
		}
		c.Detail = fmt.Sprintf("could not determine: reading %s: %v", p.auditdPID, err)
		return c
	}
	if strings.TrimSpace(string(data)) == "" {
		c.Detail = "could not determine: " + p.auditdPID + " is empty"
		return c
	}
	c.OK = true
	c.Detail = "auditd pidfile present (pid " + strings.TrimSpace(string(data)) + ")"
	return c
}

// --- sshd ------------------------------------------------------------

// sshdConfigCheck requires BOTH interactive-SSH constraints: root login
// off and password auth off. One without the other is not a pass — a box
// that permits passwords is brute-forceable whether or not root is
// reachable directly.
func sshdConfigCheck(p posturePaths) Check {
	c := Check{Name: "sshd hardened (no root login, no password auth)"}

	merged, err := readSSHDConfig(p.sshdConfig, p.sshdConfigDir)
	if err != nil {
		c.Detail = fmt.Sprintf("could not determine: %v", err)
		return c
	}

	rootLogin := sshdDirective(merged, "PermitRootLogin", "prohibit-password")
	passwordAuth := sshdDirective(merged, "PasswordAuthentication", "yes")

	var bad []string
	// "yes" is the only outright-permissive PermitRootLogin. The default
	// (prohibit-password) allows key-based root, which is normal for
	// cloud images and not what this check is about.
	if strings.EqualFold(rootLogin, "yes") {
		bad = append(bad, "PermitRootLogin="+rootLogin)
	}
	if !strings.EqualFold(passwordAuth, "no") {
		bad = append(bad, "PasswordAuthentication="+passwordAuth)
	}
	if len(bad) > 0 {
		c.Detail = strings.Join(bad, ", ")
		return c
	}
	c.OK = true
	c.Detail = fmt.Sprintf("PermitRootLogin=%s, PasswordAuthentication=%s", rootLogin, passwordAuth)
	return c
}

// readSSHDConfig concatenates the main config with its drop-in
// directory, in the order sshd itself would read them: an Include is
// expanded where it appears, and modern distros put the Include at the
// TOP of sshd_config. Since first-match-wins (below), drop-ins therefore
// override the main file — get this order backwards and the check
// reports the overridden value.
func readSSHDConfig(mainPath, dropInDir string) (string, error) {
	main, err := os.ReadFile(mainPath) // #nosec G304 -- mainPath is a package-owned constant (/etc/ssh/sshd_config), overridden only by tests
	if err != nil {
		return "", fmt.Errorf("reading %s: %w", mainPath, err)
	}
	var b strings.Builder
	entries, derr := os.ReadDir(dropInDir)
	if derr == nil {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".conf") {
				names = append(names, e.Name())
			}
		}
		sort.Strings(names) // sshd globs *.conf; lexical order is what it gets
		for _, n := range names {
			d, rerr := os.ReadFile(filepath.Join(dropInDir, filepath.Base(n))) // #nosec G304 -- dropInDir is a package-owned constant; n is Base()-bounded
			if rerr != nil {
				continue
			}
			b.Write(d)
			b.WriteString("\n")
		}
	}
	b.Write(main)
	return b.String(), nil
}

// sshdDirective returns the effective value of key, or def if unset.
//
// FIRST occurrence wins — that is OpenSSH's rule for these keywords, and
// it is the opposite of the "last wins" most config formats use. A
// last-wins implementation would report the wrong value on any host with
// a drop-in, which is most modern ones.
//
// Match blocks are ignored: a directive inside `Match` is conditional,
// and treating it as global would misreport. Anything after the first
// Match line is skipped.
func sshdDirective(config, key, def string) string {
	for _, line := range strings.Split(config, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if strings.EqualFold(fields[0], "Match") {
			break // conditional territory; stop reading globals
		}
		if strings.EqualFold(fields[0], key) && len(fields) >= 2 {
			return fields[1]
		}
	}
	return def
}

// --- unattended upgrades ---------------------------------------------

// unattendedUpgradesCheck reads APT's periodic config. Debian-family
// only; anywhere else this is an unknown rather than a failure, since
// the equivalent mechanism differs (dnf-automatic, etc.).
func unattendedUpgradesCheck(p posturePaths) Check {
	c := Check{Name: "unattended security upgrades enabled"}
	data, err := os.ReadFile(p.aptPeriodic) // #nosec G304 -- package-owned constant, overridden only by tests
	if err != nil {
		if os.IsNotExist(err) {
			c.Detail = "could not determine: " + p.aptPeriodic +
				" absent (not a Debian-family host, or unattended-upgrades never configured)"
			return c
		}
		c.Detail = fmt.Sprintf("could not determine: reading %s: %v", p.aptPeriodic, err)
		return c
	}
	if !aptPeriodicEnabled(string(data), "Unattended-Upgrade") {
		c.Detail = `APT::Periodic::Unattended-Upgrade is not "1"`
		return c
	}
	c.OK = true
	c.Detail = `APT::Periodic::Unattended-Upgrade "1"`
	return c
}

// aptPeriodicEnabled reports whether APT::Periodic::<key> is set to a
// non-zero value. APT treats "0" as off and any other integer as a day
// interval, so "7" is enabled-but-weekly, not disabled.
func aptPeriodicEnabled(config, key string) bool {
	want := "APT::Periodic::" + key
	for _, line := range strings.Split(config, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}
		if !strings.HasPrefix(line, want) {
			continue
		}
		open := strings.Index(line, `"`)
		if open < 0 {
			continue
		}
		close := strings.Index(line[open+1:], `"`)
		if close < 0 {
			continue
		}
		val := strings.TrimSpace(line[open+1 : open+1+close])
		return val != "" && val != "0"
	}
	return false
}

// --- metadata server reachability ------------------------------------

// metadataReachableCheck reports whether the cloud metadata endpoint is
// reachable from this host.
//
// #1103 asks for "IMDSv2 required", and that is not honestly checkable
// here: IMDSv2 is an AWS concept, and GCP's Metadata-Flavor header
// requirement is unconditional, so a check claiming to verify it would
// be theatre. What this issue actually cares about — given it frames
// IMDS deny as "implemented, not armed" — is whether the pivot from a
// popped workload to instance credentials is open at all. That is
// directly measurable, so it is what gets measured and what the check is
// named for.
//
// OK means UNREACHABLE. The desirable state is the connection failing.
func metadataReachableCheck(p posturePaths) Check {
	c := Check{Name: "cloud metadata endpoint blocked"}
	if p.metadataDialer == nil {
		c.Detail = "could not determine: no dialer configured"
		return c
	}
	if err := p.metadataDialer(); err != nil {
		c.OK = true
		c.Detail = "169.254.169.254:80 unreachable from the host (" + err.Error() + ")"
		return c
	}
	c.Detail = "169.254.169.254:80 is reachable from the host: a workload that escapes its container can reach instance credentials"
	return c
}

// dialMetadataServer attempts a short TCP connect to the link-local
// metadata address. Short timeout because this runs inside `doctor` and
// the daemon's status probe; a blocked address typically fails fast, but
// a DROP rule blackholes rather than refusing, so the timeout is the
// actual bound.
func dialMetadataServer() error {
	conn, err := net.DialTimeout("tcp", "169.254.169.254:80", 1500*time.Millisecond)
	if err != nil {
		return err
	}
	_ = conn.Close()
	return nil
}
