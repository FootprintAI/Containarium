package cmd

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/footprintai/containarium/internal/client"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

type fakeSessionsClient struct {
	calls  []string
	err    error
	closed bool
}

func (f *fakeSessionsClient) TerminateUserSessions(username string) (*pb.TerminateUserSessionsResponse, error) {
	f.calls = append(f.calls, username)
	if f.err != nil {
		return nil, f.err
	}
	return &pb.TerminateUserSessionsResponse{TerminatedSessions: 3, BoxesTouched: 2}, nil
}

func (f *fakeSessionsClient) Close() error { f.closed = true; return nil }

func withFakeSessionsClient(t *testing.T, f *fakeSessionsClient) {
	t.Helper()
	prev := newSessionsClient
	newSessionsClient = func() (client.SessionsAPI, error) { return f, nil }
	t.Cleanup(func() { newSessionsClient = prev })
}

func runSessionsTerminateCmd(t *testing.T, user string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	sessionsTerminateCmd.SetOut(&out)
	t.Cleanup(func() { sessionsTerminateCmd.SetOut(nil); _ = sessionsTerminateCmd.Flags().Set("user", "") })
	if err := sessionsTerminateCmd.Flags().Set("user", user); err != nil {
		t.Fatal(err)
	}
	err := sessionsTerminateCmd.RunE(sessionsTerminateCmd, nil)
	return out.String(), err
}

// The cobra command calls the client once with the username and prints the
// counts (#2522).
func TestSessionsTerminate_CallsClientOnceAndPrintsCounts(t *testing.T) {
	f := &fakeSessionsClient{}
	withFakeSessionsClient(t, f)

	out, err := runSessionsTerminateCmd(t, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if len(f.calls) != 1 || f.calls[0] != "alice" {
		t.Errorf("client calls = %v, want exactly [alice]", f.calls)
	}
	if !f.closed {
		t.Error("client not closed")
	}
	for _, want := range []string{"alice", "3", "2"} {
		if !strings.Contains(out, want) {
			t.Errorf("output %q missing %q", out, want)
		}
	}
}

func TestSessionsTerminate_RequiresUser(t *testing.T) {
	f := &fakeSessionsClient{}
	withFakeSessionsClient(t, f)
	if _, err := runSessionsTerminateCmd(t, ""); err == nil {
		t.Fatal("expected an error without --user")
	}
	if len(f.calls) != 0 {
		t.Errorf("client called without a user: %v", f.calls)
	}
}

func TestSessionsTerminate_PropagatesError(t *testing.T) {
	f := &fakeSessionsClient{err: errors.New("permission denied")}
	withFakeSessionsClient(t, f)
	if _, err := runSessionsTerminateCmd(t, "alice"); err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("err = %v", err)
	}
}
