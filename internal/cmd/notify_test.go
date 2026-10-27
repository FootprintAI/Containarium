package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/footprintai/containarium/internal/client"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

type fakeNotifyClient struct {
	set *pb.SetNotifyChannelRequest
}

func (f *fakeNotifyClient) SetNotifyChannel(req *pb.SetNotifyChannelRequest) (*pb.SetNotifyChannelResponse, error) {
	f.set = req
	return &pb.SetNotifyChannelResponse{Channel: &pb.NotifyChannel{
		Username: "alice", Server: req.GetServer(), Topic: req.GetTopic(), HasToken: req.GetToken() != "", RedactCommand: req.GetRedactCommand(),
	}}, nil
}

func (f *fakeNotifyClient) GetNotifyChannel(*pb.GetNotifyChannelRequest) (*pb.GetNotifyChannelResponse, error) {
	return &pb.GetNotifyChannelResponse{Channel: &pb.NotifyChannel{Username: "alice", Server: "https://n.example.com", Topic: "t", HasToken: true}}, nil
}

func (f *fakeNotifyClient) DeleteNotifyChannel(*pb.DeleteNotifyChannelRequest) (*pb.DeleteNotifyChannelResponse, error) {
	return &pb.DeleteNotifyChannelResponse{}, nil
}

func (f *fakeNotifyClient) TestNotifyChannel(*pb.TestNotifyChannelRequest) (*pb.TestNotifyChannelResponse, error) {
	return &pb.TestNotifyChannelResponse{Message: "test push accepted by https://n.example.com"}, nil
}

func (f *fakeNotifyClient) Close() error { return nil }

func withFakeNotifyClient(t *testing.T) *fakeNotifyClient {
	t.Helper()
	fake := &fakeNotifyClient{}
	prev := newNotifyClient
	newNotifyClient = func() (client.NotifyAPI, error) { return fake, nil }
	t.Cleanup(func() { newNotifyClient = prev })
	return fake
}

func runNotifyArgs(t *testing.T, stdin string, args ...string) (string, error) {
	t.Helper()
	for _, f := range []string{"ntfy-server", "topic", "token-file", "token-stdin", "clear-token", "redact-command"} {
		_ = notifySetNtfyCmd.Flags().Set(f, notifySetNtfyCmd.Flags().Lookup(f).DefValue)
		notifySetNtfyCmd.Flags().Lookup(f).Changed = false
	}
	var out bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&out)
	rootCmd.SetIn(strings.NewReader(stdin))
	rootCmd.SetArgs(append([]string{"--server", "daemon.example.com:50051", "notify"}, args...))
	t.Cleanup(func() { rootCmd.SetArgs(nil); rootCmd.SetIn(nil); rootCmd.SetOut(nil); rootCmd.SetErr(nil) })
	err := rootCmd.Execute()
	return out.String(), err
}

func TestNotifySetNtfy_TokenFromFile(t *testing.T) {
	fake := withFakeNotifyClient(t)
	tf := filepath.Join(t.TempDir(), "tok")
	if err := os.WriteFile(tf, []byte("tk_abc\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := runNotifyArgs(t, "", "set", "ntfy", "--ntfy-server", "https://ntfy.example.com", "--topic", "my-runs", "--token-file", tf, "--redact-command")
	if err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	r := fake.set
	if r.GetServer() != "https://ntfy.example.com" || r.GetTopic() != "my-runs" || r.GetToken() != "tk_abc" || !r.GetRedactCommand() ||
		r.GetKind() != pb.NotifyChannelKind_NOTIFY_CHANNEL_KIND_NTFY {
		t.Fatalf("request = %v", r)
	}
	if serverAddr != "daemon.example.com:50051" {
		t.Fatalf("global --server became %q", serverAddr)
	}
	if strings.Contains(out, "tk_abc") {
		t.Fatalf("output shows the token: %s", out)
	}
}

func TestNotifySetNtfy_TokenFromStdin(t *testing.T) {
	fake := withFakeNotifyClient(t)
	if out, err := runNotifyArgs(t, "tk_stdin\n", "set", "ntfy", "--ntfy-server", "https://ntfy.example.com", "--topic", "t", "--token-stdin"); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	if fake.set.GetToken() != "tk_stdin" {
		t.Fatalf("token = %q", fake.set.GetToken())
	}
}

func TestNotifySetNtfy_NoTokenFlag(t *testing.T) {
	// The global --token is the daemon's auth token; the ntfy token has no
	// flag of its own.
	for _, f := range []string{"token", "ntfy-token"} {
		if notifySetNtfyCmd.LocalNonPersistentFlags().Lookup(f) != nil {
			t.Fatalf("a --%s flag exists: the ntfy token would land in shell history", f)
		}
	}
	withFakeNotifyClient(t)
	if _, err := runNotifyArgs(t, "\n", "set", "ntfy", "--ntfy-server", "https://ntfy.example.com", "--topic", "t", "--token-stdin"); err == nil {
		t.Fatal("empty stdin token accepted")
	}
	tf := filepath.Join(t.TempDir(), "tok")
	_ = os.WriteFile(tf, []byte("x\n"), 0o600)
	if _, err := runNotifyArgs(t, "", "set", "ntfy", "--ntfy-server", "https://ntfy.example.com", "--topic", "t", "--token-file", tf, "--clear-token"); err == nil {
		t.Fatal("--clear-token with a token accepted")
	}
}

func TestNotifyShowAndTest(t *testing.T) {
	withFakeNotifyClient(t)
	out, err := runNotifyArgs(t, "", "show")
	if err != nil || !strings.Contains(out, "stored (broker-only secret)") || !strings.Contains(out, "topic:    t") {
		t.Fatalf("show: %v %s", err, out)
	}
	out, err = runNotifyArgs(t, "", "test")
	if err != nil || !strings.Contains(out, "accepted") {
		t.Fatalf("test: %v %s", err, out)
	}
}
