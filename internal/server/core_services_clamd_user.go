package server

import (
	"fmt"
	"log"
	"strings"
)

// clamdConfPath is clamd's config inside the core-security container.
const clamdConfPath = "/etc/clamav/clamd.conf"

// clamdRunAsRoot returns conf with clamd's `User` directive set to root, and
// whether anything changed. Only that one directive is touched; a conf that
// already runs clamd as root is returned as is, and one with no User line
// gets one appended (clamd then runs as whoever started it, which is root
// under systemd, but being explicit keeps the intent visible).
//
// Why root: the Debian/Ubuntu package sets `User clamav`, and the scanner
// (ScanContainer) points clamd at a tenant's rootfs. Every Linux rootfs has
// files only root can open (/etc/shadow, /etc/sudoers, ...), so clamd as
// `clamav` answers "Access denied. ERROR" for them, clamdscan exits 2, and
// the scan is recorded `incomplete` — for every box, every time (#2631).
//
// The container is unprivileged (its root is an unprivileged host uid) and
// holds only read-only mounts, so root here is contained; that is also why
// running as root is preferable to loosening the mounts.
func clamdRunAsRoot(conf string) (string, bool) {
	lines := strings.Split(conf, "\n")
	for i, raw := range lines {
		fields := strings.Fields(raw)
		if len(fields) == 0 || fields[0] != "User" {
			continue // comments start with '#', so they never match
		}
		if len(fields) == 2 && fields[1] == "root" {
			return conf, false
		}
		lines[i] = "User root"
		return strings.Join(lines, "\n"), true
	}
	if conf != "" && !strings.HasSuffix(conf, "\n") {
		conf += "\n"
	}
	return conf + "User root\n", true
}

// backfillClamdUser makes clamd run as root on a security container that was
// provisioned before this fix. Same shape as backfillConfig: run on every
// daemon start against the existing container, a no-op once converged.
//
// It restarts clamd only when the file changed. A restart reloads the whole
// signature database (about a minute), during which a scan that lands on the
// socket fails and is recorded incomplete — which is the truthful outcome.
// Failures are logged, not fatal: the next start tries again.
func (cs *CoreServices) backfillClamdUser() {
	raw, err := cs.incusClient.ReadFile(CoreSecurityContainer, clamdConfPath)
	if err != nil {
		log.Printf("Warning: could not read %s on %s to check the clamd user: %v", clamdConfPath, CoreSecurityContainer, err)
		return
	}
	fixed, changed := clamdRunAsRoot(string(raw))
	if !changed {
		return
	}
	if err := cs.incusClient.WriteFile(CoreSecurityContainer, clamdConfPath, []byte(fixed), "0644"); err != nil {
		log.Printf("Warning: failed to set clamd User=root on %s: %v", CoreSecurityContainer, err)
		return
	}
	if err := cs.incusClient.Exec(CoreSecurityContainer, []string{"systemctl", "restart", "clamav-daemon"}); err != nil {
		log.Printf("Warning: clamd.conf updated but clamav-daemon restart failed on %s: %v (scans stay incomplete until it restarts)", CoreSecurityContainer, err)
		return
	}
	log.Printf("clamd on %s now runs as root so it can read root-only files in scanned rootfs (backfill, #2631)", CoreSecurityContainer)
}

// configureClamdUser applies clamdRunAsRoot during first-time provisioning,
// before clamd is first started, so a new host never has the wrong user.
func (cs *CoreServices) configureClamdUser() error {
	raw, err := cs.incusClient.ReadFile(CoreSecurityContainer, clamdConfPath)
	if err != nil {
		return fmt.Errorf("read %s: %w", clamdConfPath, err)
	}
	fixed, changed := clamdRunAsRoot(string(raw))
	if !changed {
		return nil
	}
	if err := cs.incusClient.WriteFile(CoreSecurityContainer, clamdConfPath, []byte(fixed), "0644"); err != nil {
		return fmt.Errorf("write %s: %w", clamdConfPath, err)
	}
	return nil
}
