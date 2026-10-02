package anonbox

import (
	"context"
	"fmt"
	"path"
	"strings"
	"time"

	"github.com/footprintai/containarium/pkg/core/box"
)

// guestFiles is what the banner and claim-url need to say.
type guestFiles struct {
	expiresAt       time.Time
	limits          Limits
	previousExpired bool
	claimURL        string // empty = no claim-url file
}

// writeGuestFiles drops the login banner (and the claim URL when a minter
// is configured) into the guest. Parent directories are created first:
// the Incus file API does not create them.
func (m *Manager) writeGuestFiles(ctx context.Context, ref box.BoxRef, g guestFiles) error {
	dirs := []string{path.Dir(BannerPath), path.Dir(RemindFilePath)}
	if g.claimURL != "" && path.Dir(ClaimURLPath) != path.Dir(RemindFilePath) {
		dirs = append(dirs, path.Dir(ClaimURLPath))
	}
	if _, stderr, err := m.boxes.Exec(ctx, ref, append([]string{"mkdir", "-p"}, dirs...)); err != nil {
		return fmt.Errorf("mkdir %v: %w (%s)", dirs, err, strings.TrimSpace(stderr))
	}
	if err := m.boxes.WriteFile(ctx, ref, BannerPath, []byte(banner(g)), "0755"); err != nil {
		return fmt.Errorf("write banner: %w", err)
	}
	if g.claimURL != "" {
		if err := m.boxes.WriteFile(ctx, ref, ClaimURLPath, []byte(g.claimURL+"\n"), "0644"); err != nil {
			return fmt.Errorf("write claim-url: %w", err)
		}
	}
	// The opt-in reminder file (#2206): empty, world-writable, so the
	// unprivileged box user can opt in without a daemon credential.
	rp, rmode, rcontent := reminderGuestFile()
	if err := m.boxes.WriteFile(ctx, ref, rp, rcontent, rmode); err != nil {
		return fmt.Errorf("write remind-me file: %w", err)
	}
	return nil
}

// banner renders the update-motd.d script. The remaining time is computed
// at login (shell arithmetic against the absolute expiry) so the banner
// stays truthful for the box's whole life without rewriting it.
func banner(g guestFiles) string {
	var b strings.Builder
	b.WriteString("#!/bin/sh\n")
	fmt.Fprintf(&b, "exp=%d\n", g.expiresAt.Unix())
	b.WriteString("now=$(date +%s)\n")
	b.WriteString("left=$(( (exp - now + 59) / 60 ))\n")
	b.WriteString("echo\n")
	b.WriteString("echo '== Containarium anonymous box =='\n")
	if g.previousExpired {
		b.WriteString("echo 'Your previous box expired; this is a fresh one.'\n")
	}
	fmt.Fprintf(&b, "echo \"Expires at %s (in ${left} min), then it and its disk are destroyed.\"\n",
		g.expiresAt.UTC().Format("2006-01-02 15:04 UTC"))
	fmt.Fprintf(&b, "echo 'Limits: %s vCPU, %s RAM, %s disk. Egress: DNS, HTTP, HTTPS only. No public ports.'\n",
		g.limits.CPU, g.limits.Memory, g.limits.Disk)
	b.WriteString("echo 'This box runs on preemptible capacity and may disappear before it expires.'\n")
	b.WriteString("echo 'Keep it: run `containarium claim` and sign up with the link it prints.'\n")
	b.WriteString("echo 'Want a reminder before it expires? containarium remind-me you@example.com (opt-in, used once).'\n")
	b.WriteString("echo\n")
	return b.String()
}
