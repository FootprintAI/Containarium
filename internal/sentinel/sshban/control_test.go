package sshban

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/sentinel/sshsession"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/tg123/sshpiper/libplugin"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// TestPluginCallbacksPreserveBothFailureKinds pins upstream callback accounting
// while ensuring credential acceptance remains with the routing plugin.
func TestPluginCallbacksPreserveBothFailureKinds(t *testing.T) {
	g, _ := fixture(t, nil)
	c := g.PluginConfig()
	if c.NewConnectionCallback == nil || c.UpstreamAuthFailureCallback == nil || c.PipeCreateErrorCallback == nil || c.NoClientAuthCallback == nil {
		t.Fatal("missing enforcement callbacks")
	}
	conn := &libplugin.ConnMeta{FromAddr: "192.0.2.1:1234"}
	if err := c.NewConnectionCallback(conn); err != nil {
		t.Fatal(err)
	}
	if _, err := c.NoClientAuthCallback(conn); err != nil {
		t.Fatal(err)
	}
	c.UpstreamAuthFailureCallback(conn, "publickey", errors.New("rejected"), nil)
	c.PipeCreateErrorCallback(conn.RemoteAddr(), errors.New("pipe failed"))
	if err := c.NewConnectionCallback(conn); err == nil {
		t.Fatal("callbacks failed to ban")
	}
	if n := snapshot(t, g, "192.0.2.1").Status.GetFailures(); n != 2 {
		t.Fatalf("callback accounting changed: %d", n)
	}
	if c.PublicKeyCallback != nil || c.PasswordCallback != nil {
		t.Fatal("ban plugin must not take over credential authorization")
	}
}

// TestControlSocketQueriesEnforcementAndTargetsUnban drives the generated client
// through a real private socket, including pagination and listener ownership.
func TestControlSocketQueriesEnforcementAndTargetsUnban(t *testing.T) {
	g, _ := fixture(t, nil)
	for _, ip := range []string{"192.0.2.1", "192.0.2.2"} {
		if err := g.Check(ip + ":22"); err != nil {
			t.Fatal(err)
		}
		for range 2 {
			g.Fail(ip+":22", "auth_failure")
		}
	}
	socket := filepath.Join(t.TempDir(), "private", "control.sock")
	stop, err := ListenControl(socket, g)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	info, err := os.Stat(socket)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("socket permissions %v", info.Mode())
	}
	if another, e := ListenControl(socket, g); e == nil {
		another()
		t.Fatal("second process stole active control socket")
	}
	conn, err := grpc.NewClient("unix://"+socket, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	client := pb.NewSentinelSSHBanServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	list, err := client.ListSSHBans(ctx, &pb.ListSSHBansRequest{Listener: mainListener, PageSize: 1})
	if err != nil || len(list.GetBans()) != 1 || list.GetNextPageToken() == "" {
		t.Fatalf("page one: %v %v", list, err)
	}
	next, err := client.ListSSHBans(ctx, &pb.ListSSHBansRequest{Listener: mainListener, PageSize: 1, PageToken: list.NextPageToken})
	if err != nil || len(next.GetBans()) != 1 || next.Bans[0].Ip == list.Bans[0].Ip {
		t.Fatalf("page two: %v %v", next, err)
	}
	if _, err := client.UnbanSSHSource(ctx, &pb.UnbanSSHSourceRequest{Listener: mainListener, Ip: "192.0.2.1", Reason: "test"}); err != nil {
		t.Fatal(err)
	}
	if err := g.Check("192.0.2.1:22"); err != nil {
		t.Fatal(err)
	}
	if err := g.Check("192.0.2.2:22"); err == nil {
		t.Fatal("unban cleared other IP")
	}
}

func TestControlShutdownWaitsForInFlightRequestBeforeFinalAudit(t *testing.T) {
	rec := &captureRecorder{}
	a := NewAuditRecorder(AuditConfig{Out: rec, Listener: mainListener})
	entered, release := make(chan struct{}), make(chan struct{})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	g, now := fixture(t, func(c *Config) {
		c.Emit = func(e Event) {
			if e.Kind == EventWindowFailures {
				close(entered)
				<-release // hold the control handler before it enqueues the summary
			}
			a.Emit(e)
		}
	})
	if err := g.Check("203.0.113.1:22"); err != nil {
		t.Fatal(err)
	}
	g.Fail("203.0.113.1:22", "auth_failure")
	*now = now.Add(10 * time.Minute)
	socket := filepath.Join(t.TempDir(), "private", "control.sock")
	stop, err := ListenControl(socket, g)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	conn, err := grpc.NewClient("unix://"+socket, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	client := pb.NewSentinelSSHBanServiceClient(conn)
	requestDone := make(chan struct{})
	go func() {
		_, _ = client.GetSSHBan(context.Background(), &pb.GetSSHBanRequest{Listener: mainListener, Ip: "203.0.113.1"})
		close(requestDone)
	}()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("control request did not reach the guard")
	}
	runCtx, stopAudit := context.WithCancel(context.Background())
	defer stopAudit()
	auditDone := make(chan struct{})
	go func() { a.Run(runCtx, nil, g.TrySweep, g.FlushFailureWindows); close(auditDone) }()
	controlStopped, shutdownDone := make(chan struct{}), make(chan error, 1)
	go func() {
		stop()
		close(controlStopped)
		err := g.QuiesceCallbacks(context.Background())
		if err == nil {
			stopAudit()
			<-auditDone
		}
		shutdownDone <- err
	}()
	select {
	case <-controlStopped:
	case <-time.After(2 * time.Second):
		t.Fatal("control listener did not stop while a request was in flight")
	}
	if c, err := net.DialTimeout("unix", socket, 100*time.Millisecond); err == nil {
		_ = c.Close()
		t.Error("control socket accepted a connection after stop")
	}
	if err := runCtx.Err(); err != nil {
		t.Fatalf("audit stopped before the control request completed: %v", err)
	}
	close(release)
	select {
	case err := <-shutdownDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("shutdown did not finish after the control request")
	}
	select {
	case <-requestDone:
	case <-time.After(2 * time.Second):
		t.Fatal("control request did not finish")
	}
	recs := rec.snapshot()
	if len(recs) != 1 || recs[0].Phase != sshsession.SessionPhaseAuthFailed || recs[0].ClientIP != "203.0.113.1" || recs[0].FailureCount != 1 {
		t.Fatalf("shutdown audit records = %+v, want the in-flight control summary", recs)
	}
}

// TestControlSocketRefusesNonSocketAndSharedDirectory proves startup preserves
// existing files and refuses to expose the local admin service in a shared dir.
func TestControlSocketRefusesNonSocketAndSharedDirectory(t *testing.T) {
	g, _ := fixture(t, nil)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "state")
	if err := os.WriteFile(path, []byte("keep me"), 0600); err != nil {
		t.Fatal(err)
	}
	if stop, err := ListenControl(path, g); err == nil {
		stop()
		t.Fatal("overwrote a regular file")
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "keep me" {
		t.Fatal("destroyed existing file")
	}
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if stop, err := ListenControl(filepath.Join(dir, "other.sock"), g); err == nil {
		stop()
		t.Fatal("accepted a shared socket directory")
	}
}
