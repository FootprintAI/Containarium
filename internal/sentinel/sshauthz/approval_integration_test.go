//go:build integration && !windows

package sshauthz

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/sentinel/sshsession"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Device approval on the real chain (#2526): the stub daemon answers the
// offer APPROVAL_PENDING, the first poll PENDING again and the second ALLOW. A
// stock OpenSSH client, answering the one prompt through askpass, gets
// publickey partial success, the instruction, and a session; a noninteractive
// client is denied.
func TestIntegrationEnforceDeviceApproval(t *testing.T) {
	path, err := exec.LookPath("ssh")
	if err != nil {
		t.Skip("needs the OpenSSH client")
	}
	c := startIntegrationChain(t, "--ssh-authz-enforce")
	const instruction = "Approve this device at https://approve.example.com/d, code TEST-2526"
	var offers, polls atomic.Int32
	respond := func(req *pb.AuthorizeSSHRequest) *pb.AuthorizeSSHResponse {
		switch req.GetApprovalId() {
		case "":
			offers.Add(1)
			return &pb.AuthorizeSSHResponse{Decision: pb.SSHAuthzDecision_SSH_AUTHZ_DECISION_DENY, DenyReason: pb.SSHDenyReason_SSH_DENY_REASON_APPROVAL_PENDING,
				Approval: &pb.SSHDeviceApproval{ApprovalId: "appr-2526", Code: "TEST-2526", Url: "https://approve.example.com/d",
					PollAfter: durationpb.New(300 * time.Millisecond), ExpiresAt: timestamppb.New(time.Now().Add(30 * time.Second))}}
		case "appr-2526":
			if polls.Add(1) == 1 {
				return &pb.AuthorizeSSHResponse{Decision: pb.SSHAuthzDecision_SSH_AUTHZ_DECISION_DENY, DenyReason: pb.SSHDenyReason_SSH_DENY_REASON_APPROVAL_PENDING}
			}
			return allowed("user-approved")
		}
		t.Errorf("unexpected approval id in %v", req)
		return &pb.AuthorizeSSHResponse{Decision: pb.SSHAuthzDecision_SSH_AUTHZ_DECISION_DENY, DenyReason: pb.SSHDenyReason_SSH_DENY_REASON_APPROVAL_DENIED}
	}
	c.respond.Store(&respond)
	host, port, _ := strings.Cut(c.address, ":")
	run := func(t *testing.T, opts ...string) (stdout, stderr string, prompt []byte, err error) {
		t.Helper()
		promptFile, askpass := filepath.Join(t.TempDir(), "prompt"), filepath.Join(t.TempDir(), "askpass")
		if err := os.WriteFile(askpass, []byte("#!/bin/sh\nprintf '%s\\n' \"$1\" >> \"$SSH_AUTHZ_PROMPT_FILE\"\nprintf '\\n'\n"), 0o700); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		args := append([]string{"-vv", "-F", "/dev/null", "-T", "-p", port, "-i", filepath.Join(c.dir, "deny_key"),
			"-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
			"-o", "PreferredAuthentications=publickey,keyboard-interactive", "-o", "KbdInteractiveAuthentication=yes", "-o", "NumberOfPasswordPrompts=1"},
			opts...)
		cmd := exec.CommandContext(ctx, path, append(args, "alice@"+host, "echo audit-ok")...)
		cmd.Env = append(os.Environ(), "SSH_ASKPASS="+askpass, "SSH_ASKPASS_REQUIRE=force", "DISPLAY=ssh-authz-test:0", "SSH_AUTHZ_PROMPT_FILE="+promptFile)
		var out, errOut bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &errOut
		err = cmd.Run()
		if ctx.Err() != nil {
			t.Fatalf("OpenSSH timed out: %s", &errOut)
		}
		prompt, _ = os.ReadFile(promptFile)
		return out.String(), errOut.String(), prompt, err
	}

	t.Run("approved device opens a session", func(t *testing.T) {
		stdout, stderr, prompt, err := run(t)
		if err != nil || strings.TrimSpace(stdout) != "audit-ok" {
			t.Fatalf("session: %v\nstdout: %s\nstderr: %s", err, stdout, stderr)
		}
		if !strings.Contains(stderr, "Authenticated using \"publickey\" with partial success") || !strings.Contains(stderr, instruction) {
			t.Fatalf("missing partial success or instruction: %s", stderr)
		}
		if !strings.HasSuffix(string(prompt), "press Enter once approved: \n") || bytes.Count(prompt, []byte("\n")) != 1 {
			t.Fatalf("want exactly one prompt, got %q", prompt)
		}
		if offers.Load() != 1 || polls.Load() != 2 {
			t.Fatalf("offers=%d polls=%d, want 1 and 2", offers.Load(), polls.Load())
		}
		if rec := c.phase(t, sshsession.SessionPhaseOpen, 0); rec.UserID != "user-approved" || rec.AuthzDecision != pb.SSHAuthzDecision_SSH_AUTHZ_DECISION_ALLOW || !rec.Enforced || rec.Target != c.upstream {
			t.Fatalf("open record: %+v", rec)
		}
	})
	t.Run("noninteractive client is denied", func(t *testing.T) {
		stdout, stderr, prompt, err := run(t, "-o", "BatchMode=yes")
		if err == nil || stdout != "" || len(prompt) != 0 {
			t.Fatalf("batch client must be denied: %v\nstdout: %s\nprompt: %q\nstderr: %s", err, stdout, prompt, stderr)
		}
		if _, ok := c.tryPhase(sshsession.SessionPhaseOpen, 1); ok {
			t.Fatal("batch client opened a session")
		}
		// The key signed and the prompt was never attempted (#3084): sshpiperd's
		// connection-end notice turns the stored approval into a denied record.
		rec := c.phase(t, sshsession.SessionPhaseDenied, 0)
		if rec.DenyReason != pb.SSHDenyReason_SSH_DENY_REASON_APPROVAL_PENDING || !rec.Enforced || rec.Login != "alice" || rec.KeyFingerprint != ssh.FingerprintSHA256(c.denyKey.PublicKey()) || rec.ClientIP == "" {
			t.Fatalf("denied record for the unanswered prompt: %+v", rec)
		}
	})
}

// A client that drops while the plugin polls (#3084): the stub daemon answers
// PENDING for ever with a 250 ms poll. Once polling is under way the OpenSSH
// process is killed. The zero-prompt liveness request the plugin sends before
// each re-poll fails in sshpiperd, whose connection-end notice stops the poll:
// a few more polls at most, not the 30 seconds to expires_at (about 120 polls).
func TestIntegrationEnforceDeviceApprovalClientDropStopsPolling(t *testing.T) {
	c := startIntegrationChain(t, "--ssh-authz-enforce")
	var polls atomic.Int32
	respond := func(req *pb.AuthorizeSSHRequest) *pb.AuthorizeSSHResponse {
		if req.GetApprovalId() == "" {
			return approvalPending("appr-drop", 250*time.Millisecond, time.Now().Add(30*time.Second))
		}
		polls.Add(1)
		return &pb.AuthorizeSSHResponse{Decision: pb.SSHAuthzDecision_SSH_AUTHZ_DECISION_DENY, DenyReason: pb.SSHDenyReason_SSH_DENY_REASON_APPROVAL_PENDING}
	}
	c.respond.Store(&respond)
	a := &approvalClient{c: c}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmd, _, errOut := a.command(ctx, t)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	deadline := time.Now().Add(10 * time.Second)
	for polls.Load() < 3 {
		select {
		case err := <-done:
			t.Fatalf("client exited before polling: %v\n%s", err, errOut)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("polling never started: %s", errOut)
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel() // the client drops mid-poll
	<-done
	atDrop := polls.Load()
	time.Sleep(2 * time.Second)
	after := polls.Load()
	time.Sleep(2 * time.Second)
	if later := polls.Load(); later != after {
		t.Fatalf("polls still running after the drop: %d at drop, %d after 2s, %d after 4s", atDrop, after, later)
	}
	// One poll may be in flight when the probe fails, plus the one issued
	// right after the probe before the notice lands.
	if after-atDrop > 3 {
		t.Fatalf("%d polls after the drop, want at most 3", after-atDrop)
	}
	rec := c.phase(t, sshsession.SessionPhaseDenied, 0)
	if rec.DenyReason != pb.SSHDenyReason_SSH_DENY_REASON_APPROVAL_PENDING || !rec.Enforced || rec.KeyFingerprint != ssh.FingerprintSHA256(c.denyKey.PublicKey()) {
		t.Fatalf("denied record: %+v", rec)
	}
	assertNoSession(t, c)
}
