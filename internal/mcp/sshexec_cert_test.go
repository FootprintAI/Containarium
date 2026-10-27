package mcp

import (
	"crypto/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/connectcore"
	"golang.org/x/crypto/ssh"
)

// signTestUserCert signs pub as a user certificate for principal, valid for
// the next hour, with a fresh CA. It returns the CA's public key (what a
// server trusts) and the certificate in authorized_keys form (what
// issueCertForBox writes to "<key>-cert.pub").
func signTestUserCert(t *testing.T, pub ssh.PublicKey, principal string) (ssh.PublicKey, []byte) {
	t.Helper()
	_, caPEM, err := generateEphemeralSSHKey("test-ca")
	if err != nil {
		t.Fatalf("ca key: %v", err)
	}
	ca, err := ssh.ParsePrivateKey(caPEM)
	if err != nil {
		t.Fatalf("parse ca key: %v", err)
	}
	cert := &ssh.Certificate{
		Key:             pub,
		CertType:        ssh.UserCert,
		KeyId:           "test",
		ValidPrincipals: []string{principal},
		ValidAfter:      uint64(time.Now().Add(-time.Minute).Unix()), // #nosec G115 -- a current Unix time is positive
		ValidBefore:     uint64(time.Now().Add(time.Hour).Unix()),    // #nosec G115 -- a current Unix time is positive
	}
	if err := cert.SignCert(rand.Reader, ca); err != nil {
		t.Fatalf("sign cert: %v", err)
	}
	return ca.PublicKey(), ssh.MarshalAuthorizedKey(cert)
}

func certTestTarget(t *testing.T, srv *fakeSSHServer, user string) connectcore.Target {
	t.Helper()
	host, portStr, err := net.SplitHostPort(srv.addr())
	if err != nil {
		t.Fatalf("split addr: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}
	return connectcore.Target{User: user, Host: host, Port: port}
}

// TestRunMCPSSHExec_PresentsCertificate is the regression test for #2179:
// against a server that accepts ONLY CA-signed certificates (as the
// sentinel's sshpiper does for cert auth), the exec path must present the
// "<key>-cert.pub" issueCertForBox wrote, not the bare key.
func TestRunMCPSSHExec_PresentsCertificate(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	privPath, pub := writeManagedKey(t)
	caPub, certLine := signTestUserCert(t, pub, "tester")
	if err := os.WriteFile(privPath+"-cert.pub", certLine, 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	srv := newFakeCertSSHServer(t, caPub, "CERT_OK\n")
	defer srv.close()

	out, err := runMCPSSHExec(certTestTarget(t, srv, "tester"), privPath, "true")
	if err != nil {
		t.Fatalf("runMCPSSHExec with a certificate: %v", err)
	}
	if !strings.Contains(out, "CERT_OK") {
		t.Errorf("stdout not surfaced in:\n%s", out)
	}
}

// TestRunMCPSSHExec_BareKeyRejectedByCertOnlyServer pins down the fake
// server's side of the regression test: without the certificate file, the
// same key must be refused, so the test above can only pass by presenting it.
func TestRunMCPSSHExec_BareKeyRejectedByCertOnlyServer(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	// An auth failure is retried for authRetryWindow (#830); keep it short.
	oldW, oldI := authRetryWindow, authRetryInterval
	authRetryWindow = 300 * time.Millisecond
	authRetryInterval = 50 * time.Millisecond
	t.Cleanup(func() { authRetryWindow, authRetryInterval = oldW, oldI })

	privPath, pub := writeManagedKey(t)
	caPub, _ := signTestUserCert(t, pub, "tester")
	srv := newFakeCertSSHServer(t, caPub, "SHOULD_NOT_RUN\n")
	defer srv.close()

	if out, err := runMCPSSHExec(certTestTarget(t, srv, "tester"), privPath, "true"); err == nil {
		t.Fatalf("bare key accepted by a certificate-only server; output:\n%s", out)
	}
}

func TestWithCertIfPresent(t *testing.T) {
	privPath, pub := writeManagedKey(t)
	keyBytes, err := os.ReadFile(privPath)
	if err != nil {
		t.Fatalf("read key: %v", err)
	}
	signer, err := ssh.ParsePrivateKey(keyBytes)
	if err != nil {
		t.Fatalf("parse key: %v", err)
	}

	t.Run("no certificate file returns the key unchanged", func(t *testing.T) {
		got, err := withCertIfPresent(privPath, signer)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if _, isCert := got.PublicKey().(*ssh.Certificate); isCert {
			t.Fatal("signer unexpectedly carries a certificate")
		}
	})

	t.Run("certificate file is presented", func(t *testing.T) {
		_, certLine := signTestUserCert(t, pub, "tester")
		if err := os.WriteFile(privPath+"-cert.pub", certLine, 0o600); err != nil {
			t.Fatalf("write cert: %v", err)
		}
		defer func() { _ = os.Remove(privPath + "-cert.pub") }()
		got, err := withCertIfPresent(privPath, signer)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if _, isCert := got.PublicKey().(*ssh.Certificate); !isCert {
			t.Fatal("signer does not present the certificate")
		}
	})

	t.Run("unparseable certificate file is an error, not a fallback", func(t *testing.T) {
		if err := os.WriteFile(privPath+"-cert.pub", []byte("not a certificate\n"), 0o600); err != nil {
			t.Fatalf("write cert: %v", err)
		}
		defer func() { _ = os.Remove(privPath + "-cert.pub") }()
		if _, err := withCertIfPresent(privPath, signer); err == nil {
			t.Fatal("expected an error for a garbage certificate file")
		}
	})

	t.Run("certificate for a different key is an error", func(t *testing.T) {
		_, otherPub := writeManagedKey(t)
		_, certLine := signTestUserCert(t, otherPub, "tester")
		if err := os.WriteFile(privPath+"-cert.pub", certLine, 0o600); err != nil {
			t.Fatalf("write cert: %v", err)
		}
		defer func() { _ = os.Remove(privPath + "-cert.pub") }()
		if _, err := withCertIfPresent(privPath, signer); err == nil {
			t.Fatal("expected an error pairing a certificate issued for another key")
		}
	})
}
