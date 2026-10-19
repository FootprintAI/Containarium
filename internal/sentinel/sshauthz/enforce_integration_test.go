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

// sshpiperd v1.6.1 moves its plugin chain only forward within a connection, so
// in enforce mode the authz plugin never defers: it routes every offer itself
// and the chain never reaches yaml. A credential offered first, here a
// certificate from an untrusted CA, cannot make yaml's static authorized_keys
// the judge of a later denied key (#2629).
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
	if err := c.dial(certSigner, c.denyKey); err == nil {
		t.Fatal("certificate then denied key opened a session in enforce mode")
	}
}

// The same gap with a key the daemon ALLOWs. A publickey query needs only the
// public half, so a client holding nothing but allow_key.pub gets the query
// accepted, cannot sign, and offers the denied key on the same connection.
// OpenSSH does exactly that: in batch mode it cannot unlock the passphrase-
// protected allow_key and moves on to the next identity.
func TestIntegrationEnforceAllowThenDeny(t *testing.T) {
	path, err := exec.LookPath("ssh")
	if err != nil {
		t.Skip("needs the OpenSSH client")
	}
	c := startIntegrationChain(t, "--ssh-authz-enforce")
	allowFile := filepath.Join(c.dir, "allow_key")
	host, port, _ := strings.Cut(c.address, ":")
	out, err := exec.Command(path, "-v", "-F", "/dev/null", "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null", "-o", "ConnectTimeout=5", "-i", allowFile, "-i", filepath.Join(c.dir, "deny_key"),
		"-p", port, "alice@"+host, "true").CombinedOutput()
	if !strings.Contains(string(out), "Server accepts key: "+allowFile) {
		t.Fatalf("the allowed key's query was not accepted, so this test proves nothing: %v %s", err, out)
	}
	if err == nil {
		t.Fatalf("allowed key's query then denied key opened a session in enforce mode: %s", out)
	}
	if rec := c.phase(t, sshsession.SessionPhaseDenied, 0); rec.KeyFingerprint != ssh.FingerprintSHA256(c.denyKey.PublicKey()) || !rec.Enforced {
		t.Fatalf("denied record: %+v", rec)
	}
}

// sshpiperd copies no plugin metadata when a plugin returns the upstream, so
// in enforce mode the authz plugin writes the open and close records with the
// full field set, and ssh-session-plugin, which never sees the credential,
// writes none: one open and one close per session.
func TestIntegrationEnforceSessionRecords(t *testing.T) {
	c := startIntegrationChain(t, "--ssh-authz-enforce")
	if err := c.dial(c.allowKey); err != nil {
		t.Fatalf("allowed key refused: %v", err)
	}
	open, closed := c.phase(t, sshsession.SessionPhaseOpen, 0), c.phase(t, sshsession.SessionPhaseClose, 0)
	for _, rec := range []sshsession.Record{open, closed} {
		if rec.SessionID == "" || rec.SessionID != open.SessionID || rec.Login != "alice" || rec.Target != c.upstream || rec.ClientIP != "127.0.0.1" ||
			rec.AuthMethod != sshsession.AuthMethodPublicKey || rec.KeyFingerprint != ssh.FingerprintSHA256(c.allowKey.PublicKey()) ||
			rec.UserID != "user-allow" || rec.AuthzDecision != pb.SSHAuthzDecision_SSH_AUTHZ_DECISION_ALLOW || !rec.Enforced {
			t.Fatalf("%s record: %+v", rec.Phase, rec)
		}
	}
	if closed.CloseReason == "" {
		t.Fatalf("close record without reason: %+v", closed)
	}
	if rec, ok := c.tryPhase(sshsession.SessionPhaseOpen, 1); ok {
		t.Fatalf("second open record for one session: %+v", rec)
	}
	if rec, ok := c.tryPhase(sshsession.SessionPhaseClose, 1); ok {
		t.Fatalf("second close record for one session: %+v", rec)
	}
}
