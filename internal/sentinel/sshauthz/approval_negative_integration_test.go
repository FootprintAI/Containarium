//go:build integration && !windows

package sshauthz

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/sentinel/sshsession"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Negative wire tests for device approval (#3083). TestIntegrationEnforceDeviceApproval
// proves the approved path; these prove each way the approval stage must end
// in a refusal on the real sshpiperd chain, and that a key which never signed
// cannot borrow another key's approval.

const approvalURL = "https://approve.example.com/d"

func approvalPending(id string, poll time.Duration, expires time.Time) *pb.AuthorizeSSHResponse {
	return &pb.AuthorizeSSHResponse{Decision: pb.SSHAuthzDecision_SSH_AUTHZ_DECISION_DENY, DenyReason: pb.SSHDenyReason_SSH_DENY_REASON_APPROVAL_PENDING,
		Approval: &pb.SSHDeviceApproval{ApprovalId: id, Code: "TEST-3083", Url: approvalURL, PollAfter: durationpb.New(poll), ExpiresAt: timestamppb.New(expires)}}
}

// approvalClient runs stock OpenSSH against the chain with deny_key. The
// askpass script appends every prompt to a file, then answers with Enter, or,
// when hold is set, blocks until the test ends so the prompt is never answered.
type approvalClient struct {
	c          *integrationChain
	promptFile string
	hold       bool
	// identities are the -i files offered in order; nil offers deny_key.
	identities []string
	agent      string // SSH_AUTH_SOCK-style agent socket; empty uses no agent
	holdFile   string
}

func (a *approvalClient) command(ctx context.Context, t *testing.T) (*exec.Cmd, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	path, err := exec.LookPath("ssh")
	if err != nil {
		t.Skip("needs the OpenSSH client")
	}
	dir := t.TempDir()
	a.promptFile = filepath.Join(dir, "prompt")
	askpass, hold := filepath.Join(dir, "askpass"), filepath.Join(dir, "hold")
	a.holdFile = hold
	script := "#!/bin/sh\nprintf '%s\\n' \"$1\" >> \"$SSH_AUTHZ_PROMPT_FILE\"\n"
	if a.hold {
		if err := os.WriteFile(hold, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Remove(hold) })
		script += "while [ -e \"" + hold + "\" ]; do sleep 0.05; done\nexit 1\n"
	} else {
		script += "printf '\\n'\n"
	}
	if err := os.WriteFile(askpass, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	host, port, _ := strings.Cut(a.c.address, ":")
	ids := a.identities
	if ids == nil {
		ids = []string{filepath.Join(a.c.dir, "deny_key")}
	}
	agent := a.agent
	if agent == "" {
		agent = "none"
	}
	args := []string{"-vv", "-F", "/dev/null", "-T", "-p", port}
	for _, id := range ids {
		args = append(args, "-i", id)
	}
	cmd := exec.CommandContext(ctx, path, append(args,
		"-o", "IdentitiesOnly=yes", "-o", "IdentityAgent="+agent, "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
		"-o", "PreferredAuthentications=publickey,keyboard-interactive", "-o", "KbdInteractiveAuthentication=yes", "-o", "NumberOfPasswordPrompts=1",
		"alice@"+host, "echo audit-ok")...)
	cmd.Env = append(os.Environ(), "SSH_ASKPASS="+askpass, "SSH_ASKPASS_REQUIRE=force", "DISPLAY=ssh-authz-test:0", "SSH_AUTHZ_PROMPT_FILE="+a.promptFile)
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	return cmd, &out, &errOut
}

func (a *approvalClient) prompts() string {
	data, _ := os.ReadFile(a.promptFile)
	return string(data)
}

// run waits for the client to finish; the context bounds a hang.
func (a *approvalClient) run(t *testing.T) (stdout, stderr string, err error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd, out, errOut := a.command(ctx, t)
	err = cmd.Run()
	if ctx.Err() != nil {
		t.Fatalf("OpenSSH hung: %s", errOut)
	}
	return out.String(), errOut.String(), err
}

func assertNoSession(t *testing.T, c *integrationChain) {
	t.Helper()
	if rec, ok := c.tryPhase(sshsession.SessionPhaseOpen, 0); ok {
		t.Fatalf("a session was opened: %+v", rec)
	}
}

// The daemon answers APPROVAL_DENIED on the first poll: polling stops, the
// client is refused, and the denied record carries the daemon's reason.
func TestIntegrationEnforceDeviceApprovalDenied(t *testing.T) {
	c := startIntegrationChain(t, "--ssh-authz-enforce")
	var polls atomic.Int32
	respond := func(req *pb.AuthorizeSSHRequest) *pb.AuthorizeSSHResponse {
		if req.GetApprovalId() == "" {
			return approvalPending("appr-3083", 250*time.Millisecond, time.Now().Add(30*time.Second))
		}
		polls.Add(1)
		return &pb.AuthorizeSSHResponse{Decision: pb.SSHAuthzDecision_SSH_AUTHZ_DECISION_DENY, DenyReason: pb.SSHDenyReason_SSH_DENY_REASON_APPROVAL_DENIED}
	}
	c.respond.Store(&respond)
	a := &approvalClient{c: c}
	stdout, stderr, err := a.run(t)
	if err == nil || stdout != "" || !strings.Contains(stderr, "Permission denied") {
		t.Fatalf("a denied approval must refuse the client: %v\nstdout: %s\nstderr: %s", err, stdout, stderr)
	}
	if got := a.prompts(); !strings.HasSuffix(got, "press Enter once approved: \n") || strings.Count(got, "\n") != 1 {
		t.Fatalf("prompts = %q, want exactly one", got)
	}
	rec := c.phase(t, sshsession.SessionPhaseDenied, 0)
	if rec.DenyReason != pb.SSHDenyReason_SSH_DENY_REASON_APPROVAL_DENIED || !rec.Enforced || rec.KeyFingerprint != ssh.FingerprintSHA256(c.denyKey.PublicKey()) {
		t.Fatalf("denied record: %+v", rec)
	}
	if polls.Load() != 1 {
		t.Fatalf("polls = %d, want 1: APPROVAL_DENIED must stop polling", polls.Load())
	}
	assertNoSession(t, c)
}

// The approval expires while the daemon still answers PENDING: the plugin
// stops at expires_at instead of polling to the 60-second cap, and refuses.
func TestIntegrationEnforceDeviceApprovalExpires(t *testing.T) {
	c := startIntegrationChain(t, "--ssh-authz-enforce")
	const poll, lifetime = 250 * time.Millisecond, 1500 * time.Millisecond
	var expires time.Time
	var mu sync.Mutex
	var polls atomic.Int32
	respond := func(req *pb.AuthorizeSSHRequest) *pb.AuthorizeSSHResponse {
		mu.Lock()
		defer mu.Unlock()
		if req.GetApprovalId() == "" {
			expires = time.Now().Add(lifetime)
			return approvalPending("appr-3083", poll, expires)
		}
		polls.Add(1)
		return approvalPending("appr-3083", poll, expires)
	}
	c.respond.Store(&respond)
	a := &approvalClient{c: c}
	start := time.Now()
	stdout, stderr, err := a.run(t)
	if err == nil || stdout != "" || !strings.Contains(stderr, "Permission denied") {
		t.Fatalf("an expired approval must refuse the client: %v\nstdout: %s\nstderr: %s", err, stdout, stderr)
	}
	// Polled at least once, never past the expiry: at most lifetime/poll polls,
	// plus one for a wait cut short at the deadline. The 60-second cap would
	// poll about 240 times.
	if n := polls.Load(); n < 1 || n > int32(lifetime/poll)+2 {
		t.Fatalf("polls = %d, want 1..%d", n, int32(lifetime/poll)+2)
	}
	if took := time.Since(start); took > 10*time.Second {
		t.Fatalf("the client was held for %v past a %v approval", took, lifetime)
	}
	rec := c.phase(t, sshsession.SessionPhaseDenied, 0)
	if rec.DenyReason != pb.SSHDenyReason_SSH_DENY_REASON_APPROVAL_PENDING || !rec.Enforced {
		t.Fatalf("denied record: %+v", rec)
	}
	assertNoSession(t, c)
}

// The client's key signs and the prompt is shown, but nobody answers. The
// plugin must not poll or admit anything while the prompt is open, and when
// the client goes away the connection ends in a denied record with no session.
func TestIntegrationEnforceDeviceApprovalSignedNeverAnswered(t *testing.T) {
	c := startIntegrationChain(t, "--ssh-authz-enforce")
	var polls atomic.Int32
	respond := func(req *pb.AuthorizeSSHRequest) *pb.AuthorizeSSHResponse {
		if req.GetApprovalId() == "" {
			return approvalPending("appr-3083", 250*time.Millisecond, time.Now().Add(30*time.Second))
		}
		polls.Add(1)
		return allowed("user-approved")
	}
	c.respond.Store(&respond)
	a := &approvalClient{c: c, hold: true}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmd, _, errOut := a.command(ctx, t)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	deadline := time.Now().Add(10 * time.Second)
	for !strings.Contains(a.prompts(), "press Enter once approved") {
		select {
		case err := <-done:
			t.Fatalf("client exited before the prompt: %v\n%s", err, errOut)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("the approval prompt never reached the client: %s", errOut)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if polls.Load() != 0 {
		t.Fatalf("polls = %d while the prompt is unanswered", polls.Load())
	}
	assertNoSession(t, c)
	cancel() // the user walks away
	_ = os.Remove(a.holdFile)
	<-done
	rec := c.phase(t, sshsession.SessionPhaseDenied, 0)
	if rec.DenyReason != pb.SSHDenyReason_SSH_DENY_REASON_APPROVAL_PENDING || !rec.Enforced || rec.KeyFingerprint != ssh.FingerprintSHA256(c.denyKey.PublicKey()) {
		t.Fatalf("denied record: %+v", rec)
	}
	if polls.Load() != 0 {
		t.Fatalf("polls = %d: an unanswered prompt must never poll", polls.Load())
	}
	assertNoSession(t, c)
}

// refusingAgent is an ssh-agent that lists a victim's public key and refuses
// to sign with it, as an agent whose key is locked or confirm-gated. The
// client then moves on to its next identity on the same connection.
type refusingAgent struct{ pub ssh.PublicKey }

var errRefused = errors.New("agent refused operation")

func (a refusingAgent) List() ([]*agent.Key, error) {
	return []*agent.Key{{Format: a.pub.Type(), Blob: a.pub.Marshal(), Comment: "victim"}}, nil
}
func (refusingAgent) Sign(ssh.PublicKey, []byte) (*ssh.Signature, error) { return nil, errRefused }
func (refusingAgent) Add(agent.AddedKey) error                           { return errRefused }
func (refusingAgent) Remove(ssh.PublicKey) error                         { return errRefused }
func (refusingAgent) RemoveAll() error                                   { return errRefused }
func (refusingAgent) Lock([]byte) error                                  { return errRefused }
func (refusingAgent) Unlock([]byte) error                                { return errRefused }
func (refusingAgent) Signers() ([]ssh.Signer, error)                     { return nil, errRefused }

// A key that only queried must not reach the approval prompt after another
// key signs. The fake agent lists a victim's public key, which the daemon
// answers APPROVAL_PENDING (and would ALLOW on a poll), refuses to sign with
// it, and OpenSSH offers the denied key next. Without the clear on every
// publickey offer, the victim's approval would still be staged when the
// denied key fails, and keyboard-interactive would admit the connection as
// the victim (the issue's "clear-on-offer" regression).
func TestIntegrationEnforceDeviceApprovalFakeAgentCannotBorrow(t *testing.T) {
	c := startIntegrationChain(t, "--ssh-authz-enforce")
	victimPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	victim, err := ssh.NewPublicKey(victimPub)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	victimFile := filepath.Join(dir, "victim.pub")
	if err := os.WriteFile(victimFile, ssh.MarshalAuthorizedKey(victim), 0o600); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("unix", filepath.Join(dir, "agent.sock"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer conn.Close(); _ = agent.ServeAgent(refusingAgent{pub: victim}, conn) }()
		}
	}()
	victimFP := ssh.FingerprintSHA256(victim)
	var polls, victimOffers atomic.Int32
	respond := func(req *pb.AuthorizeSSHRequest) *pb.AuthorizeSSHResponse {
		switch {
		case req.GetApprovalId() != "":
			polls.Add(1)
			return allowed("user-victim")
		case req.GetCredential().GetPublicKey().GetFingerprintSha256() == victimFP:
			victimOffers.Add(1)
			return approvalPending("appr-victim", 250*time.Millisecond, time.Now().Add(30*time.Second))
		}
		return &pb.AuthorizeSSHResponse{Decision: pb.SSHAuthzDecision_SSH_AUTHZ_DECISION_DENY, DenyReason: pb.SSHDenyReason_SSH_DENY_REASON_UNKNOWN_KEY}
	}
	c.respond.Store(&respond)
	a := &approvalClient{c: c, agent: ln.Addr().String(), identities: []string{victimFile, filepath.Join(c.dir, "deny_key")}}
	stdout, stderr, err := a.run(t)
	if victimOffers.Load() == 0 {
		t.Fatalf("the victim's key was never offered, so this test proves nothing: %s", stderr)
	}
	if err == nil || stdout != "" || !strings.Contains(stderr, "Permission denied") {
		t.Fatalf("a connection that never signed with the victim's key must be refused: %v\nstdout: %s\nstderr: %s", err, stdout, stderr)
	}
	if got := a.prompts(); got != "" || polls.Load() != 0 {
		t.Fatalf("prompts=%q polls=%d: the victim's approval stage was reachable", got, polls.Load())
	}
	if rec := c.phase(t, sshsession.SessionPhaseDenied, 0); !rec.Enforced || rec.KeyFingerprint != ssh.FingerprintSHA256(c.denyKey.PublicKey()) {
		t.Fatalf("denied record: %+v", rec)
	}
	assertNoSession(t, c)
}
