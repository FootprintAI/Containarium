//go:build integration && !windows

package sshauthz

import (
	"crypto/rand"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/sentinel/sshsession"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"golang.org/x/crypto/ssh"
)

// Enforce mode on the real chain: the stub daemon's DENY refuses a key that
// yaml's static authorized_keys would accept, and ALLOW still opens a session.
func TestIntegrationEnforceChain(t *testing.T) {
	c := startIntegrationChain(t, "--ssh-authz-enforce")
	denyFP := ssh.FingerprintSHA256(c.denyKey.PublicKey())

	if err := c.dial(c.allowKey); err != nil {
		t.Fatalf("allowed key refused: %v", err)
	}
	if rec := c.phase(t, sshsession.SessionPhaseOpen, 0); rec.UserID != "user-allow" || rec.AuthzDecision != pb.SSHAuthzDecision_SSH_AUTHZ_DECISION_ALLOW || !rec.Enforced {
		t.Fatalf("open 0: %+v", rec)
	}

	// A client may retry a refused key on the same connection; each refusal
	// appends a denied record, and ingest keeps one row per session. Check the
	// newest record written after each attempt.
	seen := 0
	assertDenied := func(reason pb.SSHDenyReason, fp string) {
		t.Helper()
		rec := c.phase(t, sshsession.SessionPhaseDenied, seen)
		for n := seen + 1; ; n++ {
			next, ok := c.tryPhase(sshsession.SessionPhaseDenied, n)
			if !ok {
				seen = n
				break
			}
			rec = next
		}
		if !rec.Enforced || rec.Login != "alice" || rec.AuthzDecision != pb.SSHAuthzDecision_SSH_AUTHZ_DECISION_DENY || rec.DenyReason != reason || rec.KeyFingerprint != fp || rec.SessionID == "" {
			t.Fatalf("denied record: %+v", rec)
		}
	}
	if err := c.dial(c.denyKey); err == nil {
		t.Fatal("denied key opened a session in enforce mode")
	}
	assertDenied(pb.SSHDenyReason_SSH_DENY_REASON_UNKNOWN_KEY, denyFP)

	// A stock OpenSSH client reports the refusal as an ordinary key rejection.
	if path, err := exec.LookPath("ssh"); err == nil {
		host, port, _ := strings.Cut(c.address, ":")
		out, err := exec.Command(path, "-F", "/dev/null", "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=no",
			"-o", "UserKnownHostsFile=/dev/null", "-o", "ConnectTimeout=5", "-i", filepath.Join(c.dir, "deny_key"), "-p", port, "alice@"+host, "true").CombinedOutput()
		if err == nil || !strings.Contains(string(out), "Permission denied (publickey)") {
			t.Fatalf("openssh: want Permission denied (publickey), got %v: %s", err, out)
		}
		assertDenied(pb.SSHDenyReason_SSH_DENY_REASON_UNKNOWN_KEY, denyFP)
	} else {
		t.Log("ssh not on PATH; OpenSSH message not checked")
	}

	// Fail closed: a positive is honoured inside the grace window only.
	c.outage.Store(true)
	if err := c.dial(c.allowKey); err != nil {
		t.Fatalf("outage inside grace refused: %v", err)
	}
	time.Sleep(2100 * time.Millisecond)
	if err := c.dial(c.allowKey); err == nil {
		t.Fatal("outage after grace opened a session in enforce mode")
	}
	assertDenied(pb.SSHDenyReason_SSH_DENY_REASON_UPSTREAM_UNAVAILABLE, ssh.FingerprintSHA256(c.allowKey.PublicKey()))
}

// Known limitation, pinned so a fix (or an sshpiperd change) is noticed: the
// sshpiperd v1.6.1 chain only moves forward within a connection. Any offer
// this plugin defers — here a certificate from an untrusted CA — advances the
// chain to yaml, and a later offer of a denied key is then checked by yaml's
// static authorized_keys alone. See docs/SENTINEL-SSH-AUTHZ.md.
func TestIntegrationEnforceMultiOfferGap(t *testing.T) {
	c := startIntegrationChain(t, "--ssh-authz-enforce")
	ca := testKey(t)
	throwaway := testKey(t)
	cert := &ssh.Certificate{Key: throwaway.PublicKey(), CertType: ssh.UserCert, ValidPrincipals: []string{"alice"}, ValidBefore: ssh.CertTimeInfinity}
	if err := cert.SignCert(rand.Reader, ca); err != nil {
		t.Fatal(err)
	}
	certSigner, err := ssh.NewCertSigner(cert, throwaway)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.dial(c.denyKey); err == nil {
		t.Fatal("denied key alone must be refused")
	}
	if err := c.dial(certSigner, c.denyKey); err != nil {
		t.Fatalf("gap closed? certificate then denied key was refused: %v — update the doc and this test", err)
	}
}
