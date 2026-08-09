package cmd

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// #1051: `pool join` printed "Joined pool" and exited 0 while the sentinel was
// rejecting the tunnel on every reconnect — 9,423 consecutive rejections over
// 11 days on a live BYOC host, with systemctl reporting the unit active
// throughout.

// Real log lines from internal/sentinel/tunnel_client.go.
const (
	lineConnected  = `Aug 09 12:00:01 host containarium-tunnel[1]: [tunnel-client] connected to sentinel edge.example:9443`
	lineRejected   = `Aug 09 12:00:01 host containarium-tunnel[1]: [tunnel-client] connection lost: handshake rejected: invalid token`
	lineRegistered = `Aug 09 12:00:02 host containarium-tunnel[1]: [tunnel-client] registered as "tunnel-abc", assigned IP 127.0.0.11`
	lineReconnect  = `Aug 09 12:00:03 host containarium-tunnel[1]: [tunnel-client] reconnecting to edge.example:9443 (backoff: 2s)...`
)

// THE trap. "connected to sentinel" is logged when the TCP connection is
// established, BEFORE the handshake is evaluated — so a host that is rejected
// every time logs it every time. Treating it as the success marker reproduces
// the exact bug this check exists to catch, while looking correct.
//
// The dangerous window is a poll landing between the connect and the
// rejection: the journal then contains ONLY the connect line. A marker of
// "connected to sentinel" reports that as joined; the real marker reports it
// as undecided and keeps waiting.
func TestClassifyTunnelJournal_ConnectedAloneIsNotSuccess(t *testing.T) {
	outcome, _ := classifyTunnelJournal(lineConnected)
	if outcome == tunnelHandshakeRegistered {
		t.Fatal("'connected to sentinel' was treated as a successful handshake. It is logged before " +
			"the handshake is evaluated, so a host about to be rejected looks joined — #1051 exactly")
	}
	if outcome != tunnelHandshakeUnknown {
		t.Errorf("outcome = %v, want unknown while the handshake is still undecided", outcome)
	}
}

// A full reject cycle still classifies as rejected, and quotes the reason.
func TestClassifyTunnelJournal_RejectCycle(t *testing.T) {
	journal := strings.Join([]string{lineConnected, lineRejected, lineReconnect}, "\n")

	outcome, detail := classifyTunnelJournal(journal)
	if outcome != tunnelHandshakeRejected {
		t.Fatalf("outcome = %v, want rejected", outcome)
	}
	if !strings.Contains(detail, "invalid token") {
		t.Errorf("detail should quote the rejection, got %q", detail)
	}
}

func TestClassifyTunnelJournal_RegisteredIsSuccess(t *testing.T) {
	journal := strings.Join([]string{lineConnected, lineRegistered}, "\n")
	if outcome, _ := classifyTunnelJournal(journal); outcome != tunnelHandshakeRegistered {
		t.Errorf("outcome = %v, want registered", outcome)
	}
}

// Nothing decisive must NOT read as success — an empty journal is the state
// right after the unit starts.
func TestClassifyTunnelJournal_EmptyIsUnknown(t *testing.T) {
	for _, j := range []string{"", "\n", lineConnected, lineReconnect} {
		if outcome, _ := classifyTunnelJournal(j); outcome != tunnelHandshakeUnknown {
			t.Errorf("journal %q → %v, want unknown", j, outcome)
		}
	}
}

// Last decisive line wins: a host rejected on its first attempt and accepted
// after a token was registered mid-poll has genuinely joined.
func TestClassifyTunnelJournal_LastDecisiveWins(t *testing.T) {
	recovered := strings.Join([]string{lineConnected, lineRejected, lineReconnect, lineRegistered}, "\n")
	if outcome, _ := classifyTunnelJournal(recovered); outcome != tunnelHandshakeRegistered {
		t.Errorf("a rejection followed by a registration = %v, want registered", outcome)
	}

	broke := strings.Join([]string{lineRegistered, lineRejected}, "\n")
	if outcome, _ := classifyTunnelJournal(broke); outcome != tunnelHandshakeRejected {
		t.Errorf("a registration followed by a rejection = %v, want rejected", outcome)
	}
}

// The wait loop returns as soon as registration appears, rather than burning
// the full timeout on a healthy join.
func TestWaitForTunnelHandshake_ReturnsEarlyOnSuccess(t *testing.T) {
	calls := 0
	read := func(string, time.Time) (string, error) {
		calls++
		if calls < 3 {
			return lineConnected, nil
		}
		return lineConnected + "\n" + lineRegistered, nil
	}

	start := time.Now()
	outcome, _ := waitForTunnelHandshake(read, "u", time.Now(), 10*time.Second, time.Millisecond)
	if outcome != tunnelHandshakeRegistered {
		t.Fatalf("outcome = %v, want registered", outcome)
	}
	if time.Since(start) > 2*time.Second {
		t.Error("waited far longer than needed after registration appeared")
	}
}

// A rejection keeps polling to the deadline: registering the token on the
// sentinel while the join is still running should be picked up.
func TestWaitForTunnelHandshake_RejectionCanRecover(t *testing.T) {
	calls := 0
	read := func(string, time.Time) (string, error) {
		calls++
		if calls < 3 {
			return lineRejected, nil
		}
		return lineRejected + "\n" + lineRegistered, nil
	}

	outcome, _ := waitForTunnelHandshake(read, "u", time.Now(), 2*time.Second, time.Millisecond)
	if outcome != tunnelHandshakeRegistered {
		t.Errorf("outcome = %v, want registered — a rejection that later succeeds is a join", outcome)
	}
}

// A persistent rejection is reported as such.
func TestWaitForTunnelHandshake_PersistentRejection(t *testing.T) {
	read := func(string, time.Time) (string, error) { return lineRejected, nil }
	outcome, detail := waitForTunnelHandshake(read, "u", time.Now(), 30*time.Millisecond, time.Millisecond)
	if outcome != tunnelHandshakeRejected {
		t.Fatalf("outcome = %v, want rejected", outcome)
	}
	if !strings.Contains(detail, "invalid token") {
		t.Errorf("detail = %q", detail)
	}
}

// An unreadable journal must not fail the join. Hosts without journald have to
// stay joinable; "could not confirm" is the honest outcome, not an error.
func TestWaitForTunnelHandshake_UnreadableJournalIsUnknown(t *testing.T) {
	read := func(string, time.Time) (string, error) { return "", errors.New("journalctl: not found") }
	outcome, _ := waitForTunnelHandshake(read, "u", time.Now(), 20*time.Millisecond, time.Millisecond)
	if outcome != tunnelHandshakeUnknown {
		t.Errorf("outcome = %v, want unknown — a host without journald must still be able to join", outcome)
	}
}

// The failure message has to carry the remedy. The reason this bug cost 11
// days is that the obvious remedy (mint a new token, re-join) reproduces the
// identical failure, so an error that only reports the symptom sends the
// operator round the same loop.
func TestTunnelRejectedErrorNamesTheRemedy(t *testing.T) {
	err := tunnelRejectedError("edge.example:9443", "tunnel-abc", "handshake rejected: invalid token")
	msg := err.Error()

	for _, want := range []struct{ text, why string }{
		{"register-token", "the actual fix"},
		{"do not expire", "why re-joining will not help — the whole trap"},
		{"admin secret", "register-token is gated, and a sentinel without the secret cannot do it at all"},
		{"journalctl -u containarium-tunnel", "where to look"},
		{"edge.example:9443", "which sentinel"},
		{"tunnel-abc", "which host"},
		{"invalid token", "the observed rejection"},
	} {
		if !strings.Contains(msg, want.text) {
			t.Errorf("error message is missing %q (%s):\n%s", want.text, want.why, msg)
		}
	}

	if strings.Contains(msg, "Joined pool") {
		t.Error("the failure must not also claim the pool was joined")
	}
}
