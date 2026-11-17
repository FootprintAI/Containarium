package guardraildropin

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// The built-in engine (#3767): the in-tree reference rules engine, run from
// the pinned binary as a systemd service of the box. Its unit and socket
// have names of their own. A separately packaged engine keeps
// containarium-engine.service and /run/containarium-engine; the daemon
// never writes a unit under that name.
const (
	// EngineBuiltin as Options.EngineUnit means the daemon installs and
	// runs the reference engine itself. Any other value names a unit the
	// operator provides, and the daemon installs none.
	EngineBuiltin = "builtin"
	// ReferenceEngineUnit is the unit the daemon installs.
	ReferenceEngineUnit = "containarium-guardrail-reference-engine.service"
	// referenceRuntimeDir is the unit's RuntimeDirectory, under /run.
	referenceRuntimeDir = "containarium-guardrail-reference"
	// ReferenceEngineSocket is where the built-in engine listens.
	ReferenceEngineSocket = "/run/" + referenceRuntimeDir + "/engine.sock"
	// ReferenceEngineAddr is ReferenceEngineSocket as an --engine address.
	ReferenceEngineAddr = "unix://" + ReferenceEngineSocket
	// EngineGroup may open the engine's socket (mode 0660). The box user is
	// added to it; the socket's mode is never widened.
	EngineGroup = "guardrail"
	// EngineUser runs the built-in engine. A system account with no shell
	// and no home.
	EngineUser = "containarium-guardrail"

	systemdDir = "/etc/systemd"
	unitDir    = systemdDir + "/system"
	// EngineUnitPath is the unit file in the box.
	EngineUnitPath = unitDir + "/" + ReferenceEngineUnit
	// tmpUnitPath does not end in .service, so systemd never loads it.
	tmpUnitPath = unitDir + "/.containarium-guardrail-reference-engine.tmp"
)

// errEngineNotReady is a built-in engine that did not start, or whose
// socket the box user cannot open. No drop-in is left behind in that case.
var errEngineNotReady = errors.New("the built-in engine is not ready in this box")

// RenderEngineUnit returns the unit file's bytes. Deterministic, so the
// coverage check can compare a box's file against it.
//
// Every hardening directive here is a seccomp filter, a prctl or a
// capability drop, which work for a non-root service inside an unprivileged
// system container. Directives that build a mount or network namespace
// (ProtectSystem=, PrivateTmp=, PrivateNetwork=, ...) are left out: whether
// they work depends on the container's nesting and AppArmor settings, and a
// unit that fails to start blocks every tool call in the box.
// RestrictAddressFamilies=AF_UNIX is what gives "no network": the process
// cannot create an IP socket at all.
func RenderEngineUnit() []byte {
	return []byte(`# Installed by the Containarium daemon. Do not edit: the daemon replaces
# this file, and removes it when the guardrail hook is switched off.
[Unit]
Description=Containarium guardrail reference engine

[Service]
Type=notify
NotifyAccess=main
ExecStart=` + HookBinaryPath + ` guardrail engine serve --listen ` + ReferenceEngineAddr + `
User=` + EngineUser + `
Group=` + EngineGroup + `
RuntimeDirectory=` + referenceRuntimeDir + `
RuntimeDirectoryMode=0750
UMask=0117
Restart=on-failure
RestartSec=1
TimeoutStartSec=8
NoNewPrivileges=yes
CapabilityBoundingSet=
AmbientCapabilities=
RestrictAddressFamilies=AF_UNIX
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
`)
}

// engineAccountsScript makes the group $1 and the system user $2 if they
// are missing, and adds the box user $3 to the group. groupadd, useradd and
// usermod are in every box image (the box user itself is made with them);
// each step is skipped when it is already done.
const engineAccountsScript = `getent group "$1" >/dev/null || groupadd -r -- "$1" || { echo "cannot create group $1"; exit 3; }
getent passwd "$2" >/dev/null || useradd -r -g "$1" -M -d /nonexistent -s /usr/sbin/nologin -- "$2" || { echo "cannot create user $2"; exit 3; }
id -nG -- "$3" | tr ' ' '\n' | grep -qx -- "$1" || usermod -aG "$1" -- "$3" || { echo "cannot add $3 to group $1"; exit 3; }`

// removeEngineScript stops the unit $1 and removes its file $2 and the
// temporary $3. It succeeds on a box that never had the unit, and on one
// with no systemd. The group, the engine's user and the box user's
// membership stay: the group is shared with a separately packaged engine,
// and membership grants nothing but the engine's socket.
const removeEngineScript = `systemctl stop "$1" >/dev/null 2>&1
[ -e "$2" ] || [ -L "$2" ] || [ -e "$3" ] || [ -L "$3" ] || exit 0
systemctl disable "$1" >/dev/null 2>&1
rm -f -- "$2" "$3" || exit 3
systemctl daemon-reload >/dev/null 2>&1
exit 0`

// installEngine brings the box's engine in line with the daemon's flags,
// after the pinned binary is in place and before the drop-in is written.
// Built-in: accounts, unit, start, then the socket as the box user.
// Otherwise: nothing, except taking out a unit an earlier built-in
// configuration left.
func (c *checker) installEngine(container, user string, binaryChanged bool) error {
	nodes, err := c.stat(container, EngineUnitPath)
	if err != nil {
		return err
	}
	if !c.builtin {
		if nodes[0].missing {
			return nil
		}
		return c.removeEngine(container)
	}
	if out, code, err := c.run.script(container, prepareDirsScript, systemdDir, unitDir); err != nil {
		return err
	} else if code != 0 {
		return fmt.Errorf("refusing to write into %q: %s", container, strconv.Quote(strings.TrimSpace(out)))
	}
	if out, code, err := c.run.script(container, engineAccountsScript, EngineGroup, EngineUser, user); err != nil {
		return err
	} else if code != 0 {
		return fmt.Errorf("engine accounts in %q: %s", container, strconv.Quote(strings.TrimSpace(out)))
	}

	unit := RenderEngineUnit()
	have := ""
	if nodes[0].rootFile() {
		if have, err = c.boxSHA(container, EngineUnitPath); err != nil {
			return err
		}
	}
	unitChanged := have != sha256Hex(unit)
	if unitChanged {
		if err := c.run.mustRun(container, "rm", "-f", "--", tmpUnitPath); err != nil {
			return err
		}
		if err := c.run.push(container, func() error { return c.box.WriteFile(container, tmpUnitPath, unit, "0644") }); err != nil {
			return fmt.Errorf("install engine unit in %q: %w", container, err)
		}
		if err := c.run.mustRun(container, "mv", "-T", "--", tmpUnitPath, EngineUnitPath); err != nil {
			return err
		}
		if err := c.run.mustRun(container, "systemctl", "daemon-reload"); err != nil {
			return err
		}
	}
	// Enabled, so the engine is up at the box's next boot before any
	// session is.
	if err := c.run.mustRun(container, "systemctl", "enable", "--quiet", ReferenceEngineUnit); err != nil {
		return err
	}
	// The unit is Type=notify: start returns once the engine listens. A
	// new binary or unit needs a restart to take effect.
	verb := "start"
	if unitChanged || binaryChanged {
		verb = "restart"
	}
	if err := c.run.mustRun(container, "systemctl", verb, ReferenceEngineUnit); err != nil {
		return fmt.Errorf("%w: %v (does the pinned binary have `guardrail engine serve`? see `journalctl -u %s` in the box)", errEngineNotReady, err, ReferenceEngineUnit)
	}
	_, code, err := c.run.run(container, c.socketTest(user)...)
	if err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("%w: the box user cannot open %s", errEngineNotReady, ReferenceEngineSocket)
	}
	return nil
}

// socketTest is the command that tests the engine's socket as a fresh
// process of the box user, the way a hook opens it.
func (c *checker) socketTest(user string) []string {
	return []string{"runuser", "-u", user, "--", "test", "-S", c.socket, "-a", "-r", c.socket, "-a", "-w", c.socket}
}

// removeEngine stops and removes the daemon's unit, if there is one.
func (c *checker) removeEngine(container string) error {
	out, code, err := c.run.script(container, removeEngineScript, ReferenceEngineUnit, EngineUnitPath, tmpUnitPath)
	if err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("remove engine unit in %q: exit %d %s", container, code, strconv.Quote(strings.TrimSpace(out)))
	}
	return nil
}

// checkUnitFile is the coverage check of the built-in engine's unit file:
// present, a closed root-owned regular file, and the one this daemon
// renders. The zero Result means it is.
func (c *checker) checkUnitFile(container string, prev installed) (Result, error) {
	nodes, err := c.stat(container, EngineUnitPath)
	if err != nil {
		return Result{}, err
	}
	earlier := Result{repair: true, stale: true, Detail: "the engine unit is from an earlier daemon version or configuration"}
	switch n := nodes[0]; {
	case n.missing && prev.unit == "":
		return earlier, nil
	case n.missing:
		return notInstalled(EngineUnitPath + " is missing"), nil
	case !n.rootFile():
		return tampered(EngineUnitPath+" is not a regular root-owned file closed to group and others", true), nil
	}
	have, err := c.boxSHA(container, EngineUnitPath)
	if err != nil {
		return Result{}, err
	}
	switch {
	case have == sha256Hex(RenderEngineUnit()):
		return Result{}, nil
	case have == prev.unit:
		return earlier, nil
	}
	return tampered("the engine unit differs from what the daemon installed", true), nil
}
