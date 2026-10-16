//go:build integration && linux

package sshban

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/sentinel/sshcontrol"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/types/known/durationpb"
)

// guardedControl runs the production private service with an elapsed initial hold.
func guardedControl(t *testing.T, backend string, window time.Duration, extraBackends ...string) (*sshcontrol.Controller, string) {
	t.Helper()
	dir, err := os.MkdirTemp("", "upstream-integration-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	var offset atomic.Int64
	offset.Store(int64(-window))
	p := &pb.SSHUpstreamPolicy{InitialDelay: durationpb.New(time.Second), MaxDelay: durationpb.New(8 * time.Second), Window: durationpb.New(window), SetupTimeout: durationpb.New(3 * time.Second), FailureBudget: 2, RiskPerAttempt: 1, MaxBackends: 8, MaxPending: 8, MaxConnections: 1024, Jitter: 0.25, EgressGroup: "sentinel-loopback", Routes: []*pb.SSHUpstreamRoute{{BackendId: "backend", Endpoint: backend}}}
	for _, endpoint := range extraBackends {
		p.Routes = append(p.Routes, &pb.SSHUpstreamRoute{BackendId: "healthy/" + endpoint, Endpoint: endpoint})
	}
	c, err := sshcontrol.New(sshcontrol.Config{Policy: p, StatePath: filepath.Join(dir, "risk.json"), Now: func() time.Time { return time.Now().Add(time.Duration(offset.Load())) }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	// Only startup is advanced. All live leases, retry timing and jail records
	// use real wall time; the long outage is never compressed by this clock.
	offset.Store(0)
	socket := filepath.Join(dir, "control.sock")
	stop, err := sshcontrol.ListenControl(socket, c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(stop)
	return c, socket
}

// abortSignatureSigner aborts after the allowed-key probe, before signing auth.
type abortSignatureSigner struct{ ssh.Signer }

// Sign simulates a client abandoning a valid key instead of authenticating it.
func (s abortSignatureSigner) Sign(io.Reader, []byte) (*ssh.Signature, error) {
	return nil, errors.New("synthetic downstream abort before signature")
}

// TestIntegrationGuardedSSHAbandonedClientRisk characterizes the pinned API limit.
// A key probe can reach the backend before downstream signature verification;
// without a typed backend-ready event an aborted setup retains uncertain risk.
func TestIntegrationGuardedSSHAbandonedClientRisk(t *testing.T) {
	backend := retryUnusedAddress(t)
	_, socket := guardedControl(t, backend, 10*time.Minute)
	f := newConfiguredRetryFixture(t, 100, 1, retryMode{routed: true, controlSocket: socket, backend: backend})
	f.retryBackend(t)
	for i := range 2 {
		if err := retryHandshake(f.addr, "127.0.0.2", abortSignatureSigner{f.keys[0]}); err == nil {
			t.Fatal("unsigned client authenticated")
		}
		if i == 0 {
			time.Sleep(1300 * time.Millisecond)
		}
	}
	if got := len(f.attempts(t)); got != 2 {
		t.Fatalf("abandoned key probes made %d backend dials, want two", got)
	}
	if err := retryHandshake(f.addr, "127.0.0.3", f.keys[0]); err == nil {
		t.Fatal("unknown post-dial aborts were refunded without backend outcome proof")
	}
	if got := len(f.attempts(t)); got != 2 {
		t.Fatal("exhausted uncertain risk admitted another backend dial")
	}
	t.Log("confirmed review item 7: two unsigned key-probe aborts retain two risk units; a typed pre-signature backend-ready callback is required to refund safely")
}

// wrongSignatureSigner offers an allowed public key without possessing its secret.
type wrongSignatureSigner struct {
	allowed ssh.PublicKey
	wrong   ssh.Signer
}

// PublicKey deliberately offers an identity that the routing child allows.
func (s wrongSignatureSigner) PublicKey() ssh.PublicKey { return s.allowed }

// Sign proves possession of a different key so real sshpiperd must reject it.
func (s wrongSignatureSigner) Sign(r io.Reader, data []byte) (*ssh.Signature, error) {
	return s.wrong.Sign(r, data)
}

// TestIntegrationGuardedSSHClientFailures keeps signatures/passwords accountable.
func TestIntegrationGuardedSSHClientFailures(t *testing.T) {
	for _, password := range []bool{false, true} {
		t.Run(map[bool]string{false: "signature", true: "password"}[password], func(t *testing.T) {
			backend := retryUnusedAddress(t)
			_, socket := guardedControl(t, backend, 10*time.Minute)
			f := newConfiguredRetryFixture(t, 100, 1, retryMode{routed: true, password: password, controlSocket: socket, backend: backend})
			f.retryBackend(t)
			if password {
				if err := retryHandshakeAuth(f.addr, "127.0.0.2", ssh.Password("wrong")); err == nil {
					t.Fatal("invalid password authenticated")
				}
			} else {
				_, wrong := integrationKey(t, t.TempDir(), "signature-wrong")
				if err := retryHandshake(f.addr, "127.0.0.2", wrongSignatureSigner{allowed: f.keys[0].PublicKey(), wrong: wrong}); err == nil {
					t.Fatal("forged key signature authenticated")
				}
			}
			if got := f.waitForFailures(t, "127.0.0.2", 1).Status.GetFailures(); got < 1 {
				t.Fatal("client denial no longer counted")
			}
		})
	}
}

// TestIntegrationGuardedSSHRefusal shares cooldown across real main/anon chains.
func TestIntegrationGuardedSSHRefusal(t *testing.T) {
	backend := retryUnusedAddress(t)
	_, socket := guardedControl(t, backend, 10*time.Minute)
	main := newConfiguredRetryFixture(t, 2, 1, retryMode{routed: true, controlSocket: socket, backend: backend})
	anon := newConfiguredRetryFixture(t, 2, 1, retryMode{routed: true, anonymous: true, controlSocket: socket, backend: backend})
	for range 4 {
		if err := retryHandshake(main.addr, "127.0.0.2", main.keys[0]); err == nil {
			t.Fatal("refused main backend authenticated")
		}
		if err := retryHandshake(anon.addr, "127.0.0.2", anon.keys[0]); err == nil {
			t.Fatal("refused anonymous backend authenticated")
		}
	}
	if got := len(main.attempts(t)) + len(anon.attempts(t)); got != 1 {
		t.Fatalf("cross-listener cooldown permitted %d actual backend dials", got)
	}
	for _, f := range []*retryFixture{main, anon} {
		if got := f.status(t, "127.0.0.2").Status.GetFailures(); got != 0 {
			t.Fatalf("backend outage charged %d client failures", got)
		}
	}
	main.retryBackend(t)
	time.Sleep(1300 * time.Millisecond) // exceed the explicitly jittered first cooldown
	if err := retryHandshake(main.addr, "127.0.0.2", main.keys[0]); err != nil {
		t.Fatalf("SSH-ready recovery probe failed: %v", err)
	}
	_, bad := integrationKey(t, t.TempDir(), "unauthorized")
	if err := retryHandshake(main.addr, "127.0.0.3", bad); err == nil {
		t.Fatal("guard bypassed YAML key authorization")
	}
	if got := main.waitForFailures(t, "127.0.0.3", 1).Status.GetFailures(); got < 1 {
		t.Fatal("invalid client key no longer counted")
	}
}

// TestIntegrationGuardedSSHProxyFailure reserves jail risk before another dial.
func TestIntegrationGuardedSSHProxyFailure(t *testing.T) {
	backend := retryUnusedAddress(t)
	_, socket := guardedControl(t, backend, 10*time.Minute)
	f := newConfiguredRetryFixture(t, 2, 1, retryMode{routed: true, controlSocket: socket, backend: backend})
	_, wrong := integrationKey(t, t.TempDir(), "wrong-proxy")
	f.upstream = wrong
	f.retryBackend(t)
	for range 4 {
		if err := retryHandshake(f.addr, "127.0.0.2", f.keys[0]); err == nil {
			t.Fatal("wrong configured proxy key authenticated")
		}
	}
	if got := len(f.attempts(t)); got != 1 {
		t.Fatalf("proxy rejection produced %d dials, want one", got)
	}
	if got := f.status(t, "127.0.0.2").Status.GetFailures(); got != 0 {
		t.Fatalf("proxy failure charged %d client failures", got)
	}
}
