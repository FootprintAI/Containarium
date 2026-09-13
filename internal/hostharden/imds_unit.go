package hostharden

import (
	"fmt"
	"os"
	"strings"
)

// ImdsBlockUnitPath is the systemd unit BlockMetadataFromBridge's rule
// needs to survive a reboot — `iptables` rules are runtime kernel state,
// not persisted by the package itself, and this repo doesn't assume any
// particular distro's persistence mechanism (iptables-persistent,
// netfilter-persistent, firewalld) is installed. A oneshot unit that
// re-runs the same idempotent check-then-insert this package already does
// is simpler than depending on one of those and works everywhere systemd
// does.
const ImdsBlockUnitPath = "/etc/systemd/system/containarium-imds-block.service"

// InstallPersistentUnit writes and enables a systemd oneshot unit that
// re-applies BlockMetadataFromBridge's rule on every boot. Idempotent:
// re-running (e.g. on a re-enroll) overwrites the same content and
// `systemctl enable` on an already-enabled unit is a no-op.
//
// containariumBin is the path to this binary (os.Executable()) — the unit
// shells out to `containarium hostharden block-metadata <bridge>` rather
// than duplicating the iptables/incus invocation inline, so the unit and
// this package can never drift.
func InstallPersistentUnit(containariumBin, bridge string) error {
	return installPersistentUnit(defaultRunner, ImdsBlockUnitPath, containariumBin, bridge)
}

func installPersistentUnit(run runner, unitPath, containariumBin, bridge string) error {
	unit := fmt.Sprintf(`[Unit]
Description=Re-apply the BYOC metadata-endpoint FORWARD block (#1103) after reboot
After=network-online.target incus.socket
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=%s hostharden block-metadata %s
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
`, containariumBin, bridge)

	if err := os.WriteFile(unitPath, []byte(unit), 0o644); err != nil { // #nosec G306 -- a systemd unit file is meant to be world-readable; it carries no secret (containariumBin/bridge are non-sensitive paths/names)
		return fmt.Errorf("write %s: %w", unitPath, err)
	}
	if out, err := run("systemctl", "daemon-reload"); err != nil {
		return fmt.Errorf("systemctl daemon-reload: %w: %s", err, strings.TrimSpace(string(out)))
	}
	if out, err := run("systemctl", "enable", "--now", "containarium-imds-block.service"); err != nil {
		return fmt.Errorf("systemctl enable --now containarium-imds-block.service: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
