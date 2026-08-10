package cmd

import (
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// Post-join verification that the tunnel handshake actually succeeded (#1051).
//
// `pool join` used to print `Joined pool ...` and exit 0 as soon as the units
// were enabled and the host-side capability check passed. Both are host-side
// facts. Nothing asked the sentinel whether the tunnel had been accepted, so a
// tunnel being rejected on every reconnect looked exactly like a healthy join.
//
// A live BYOC host accumulated 9,423 consecutive `handshake rejected: invalid
// token` rejections over 11 days that way, with `systemctl is-active` cheerful
// throughout. The operator's only signal was a journal they had no reason to
// open.
//
// The non-obvious part, and the reason a bare "check the logs" hint is not
// enough: tunnel-join tokens DO NOT EXPIRE. Re-joining mints another token
// that is unregistered in exactly the same way, so the intuitive remedy
// reproduces the identical failure. The sentinel builds its token policy once
// at startup, so any token minted afterwards — which is every token the cloud
// BYOC flow issues — needs `sentinel register-token` before it can ever work.
// That is what the failure message has to say.

// tunnelHandshakeOutcome is what the tunnel unit's journal shows about the
// most recent handshake attempt.
type tunnelHandshakeOutcome int

const (
	// tunnelHandshakeUnknown: nothing decisive in the journal yet. Not a
	// failure — the unit may still be starting, or journald may be
	// unavailable — but not a success either.
	tunnelHandshakeUnknown tunnelHandshakeOutcome = iota
	// tunnelHandshakeRegistered: the sentinel accepted the tunnel.
	tunnelHandshakeRegistered
	// tunnelHandshakeRejected: the sentinel refused the handshake.
	tunnelHandshakeRejected
)

func (o tunnelHandshakeOutcome) String() string {
	switch o {
	case tunnelHandshakeRegistered:
		return "registered"
	case tunnelHandshakeRejected:
		return "rejected"
	default:
		return "unknown"
	}
}

// Markers emitted by internal/sentinel/tunnel_client.go.
//
// registeredMarker is deliberately NOT "connected to sentinel": that is
// logged when the TCP connection is established, BEFORE the handshake is
// evaluated, so a host being rejected on every attempt logs it every time.
// Treating it as success would reproduce the very bug this check exists to
// catch. "registered as" is logged only after the sentinel accepts.
const (
	tunnelRegisteredMarker = "registered as"
	tunnelRejectedMarker   = "handshake rejected"
)

// classifyTunnelJournal reports the outcome of the LAST decisive handshake
// line in a journal excerpt, along with that line for context.
//
// Last-wins because the journal is chronological and both markers can appear
// in one window: a host rejected on its first attempt and accepted after a
// token was registered mid-poll has genuinely joined, and must not be
// reported as broken.
func classifyTunnelJournal(journal string) (tunnelHandshakeOutcome, string) {
	outcome := tunnelHandshakeUnknown
	var detail string

	for _, line := range strings.Split(journal, "\n") {
		switch {
		case strings.Contains(line, tunnelRejectedMarker):
			outcome, detail = tunnelHandshakeRejected, strings.TrimSpace(line)
		case strings.Contains(line, tunnelRegisteredMarker):
			outcome, detail = tunnelHandshakeRegistered, strings.TrimSpace(line)
		}
	}
	return outcome, detail
}

// journalReader returns recent log text for a unit. Injectable so the wait
// loop is testable without systemd.
type journalReader func(unit string, since time.Time) (string, error)

// validUnitName matches the systemd unit names this package is allowed to
// read. Deliberately strict: the name becomes a command argument, and a
// leading dash would be parsed as a flag.
var validUnitName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9@._-]*$`)

// readUnitJournal is the real reader.
func readUnitJournal(unit string, since time.Time) (string, error) {
	// The unit name is a package constant at the only call site, but it is a
	// parameter for testability — so validate rather than assume, and keep
	// the check next to the exec that depends on it.
	if !validUnitName.MatchString(unit) {
		return "", fmt.Errorf("refusing to read the journal for %q: not a valid unit name", unit)
	}

	// #nosec G204 -- the binary is the literal "journalctl"; the only
	// non-literal argument is the unit name, which is validated immediately
	// above and never reaches a shell (exec.Command does not use one).
	out, err := exec.Command("journalctl",
		"-u", unit,
		"--since", since.Format("2006-01-02 15:04:05"),
		"--no-pager", "-n", "200",
	).CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("read journal for %s: %w", unit, err)
	}
	return string(out), nil
}

// waitForTunnelHandshake polls the unit journal until the handshake is
// decisively registered or rejected, or the timeout elapses.
//
// Returns Unknown rather than an error when the journal is unreadable: a host
// without journald must still be able to join. Reporting "could not confirm"
// is honest; failing the join would be a regression for those hosts.
func waitForTunnelHandshake(read journalReader, unit string, since time.Time, timeout, poll time.Duration) (tunnelHandshakeOutcome, string) {
	if poll <= 0 {
		poll = 500 * time.Millisecond
	}
	deadline := time.Now().Add(timeout)

	var lastOutcome = tunnelHandshakeUnknown
	var lastDetail string
	for {
		journal, err := read(unit, since)
		if err == nil {
			if outcome, detail := classifyTunnelJournal(journal); outcome != tunnelHandshakeUnknown {
				// A rejection can be followed by a success once a token is
				// registered, but not the other way round within one join, so
				// a registration is final. Keep polling through a rejection
				// until the deadline in case it recovers.
				lastOutcome, lastDetail = outcome, detail
				if outcome == tunnelHandshakeRegistered {
					return outcome, detail
				}
			}
		}
		if !time.Now().Before(deadline) {
			return lastOutcome, lastDetail
		}
		time.Sleep(poll)
	}
}

// tunnelRejectedError builds the failure the operator needs, naming the
// remedy rather than the symptom.
func tunnelRejectedError(sentinelAddr, spotID, detail string) error {
	return fmt.Errorf(`pool join: the sentinel REJECTED this host's tunnel handshake — the units are installed but this host is NOT joined

  %s

Re-running `+"`pool join`"+` will NOT fix this: tunnel-join tokens do not expire, so a
fresh token fails in exactly the same way. The sentinel builds its token policy
once at startup, so a token minted afterwards (which is every token a cloud BYOC
join issues) has to be registered with the running sentinel first:

  containarium sentinel register-token --url https://%s --token <the join token>

That call is gated on the sentinel's admin secret. If the sentinel was started
without CONTAINARIUM_SENTINEL_ADMIN_SECRET, token registration is disabled
entirely and the sentinel must be restarted with --tunnel-token-policy instead.

  Tunnel logs: sudo journalctl -u containarium-tunnel -n 50
  Spot ID:     %s`, detail, sentinelAddr, spotID)
}
