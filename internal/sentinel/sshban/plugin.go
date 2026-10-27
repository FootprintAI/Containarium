package sshban

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/footprintai/containarium/internal/sentinel/sshcontrol"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/tg123/sshpiper/libplugin"
)

var errCallbacksClosed = errors.New("ssh-ban plugin is shutting down")

func (g *Guard) beginCallback() bool {
	g.callbackMu.Lock()
	defer g.callbackMu.Unlock()
	if g.callbacksClosed {
		return false
	}
	if g.callbacksActive == 0 {
		g.callbacksDone = make(chan struct{})
	}
	g.callbacksActive++
	return true
}

func (g *Guard) endCallback() {
	g.callbackMu.Lock()
	defer g.callbackMu.Unlock()
	g.callbacksActive--
	if g.callbacksActive == 0 {
		close(g.callbacksDone)
	}
}

// QuiesceCallbacks rejects new plugin callbacks and control RPCs, then waits
// for accepted requests. A deadline bounds the wait for a stuck request.
func (g *Guard) QuiesceCallbacks(ctx context.Context) error {
	g.callbackMu.Lock()
	g.callbacksClosed = true
	if g.callbacksActive == 0 {
		g.callbackMu.Unlock()
		return nil
	}
	done := g.callbacksDone
	g.callbackMu.Unlock()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		select {
		case <-done:
			return nil
		default:
		}
		return fmt.Errorf("waiting for SSH-ban callbacks: %w", ctx.Err())
	}
}

// PluginConfig preserves the bundled failtoban's callback and routing contract.
func (g *Guard) PluginConfig(peers ...*sshcontrol.Peer) libplugin.SshPiperPluginConfig {
	cfg := libplugin.SshPiperPluginConfig{
		NoClientAuthCallback: func(libplugin.ConnMetadata) (*libplugin.Upstream, error) {
			if !g.beginCallback() {
				return nil, errCallbacksClosed
			}
			defer g.endCallback()
			return &libplugin.Upstream{Auth: libplugin.CreateNextPluginAuth(map[string]string{})}, nil
		},
		NewConnectionCallback: func(conn libplugin.ConnMetadata) error {
			if !g.beginCallback() {
				return errCallbacksClosed
			}
			defer g.endCallback()
			return g.Check(conn.RemoteAddr())
		},
		UpstreamAuthFailureCallback: func(conn libplugin.ConnMetadata, _ string, _ error, _ []string) {
			if !g.beginCallback() {
				return
			}
			defer g.endCallback()
			g.Fail(conn.RemoteAddr(), "auth_failure")
		},
		PipeCreateErrorCallback: func(remote string, _ error) {
			if !g.beginCallback() {
				return
			}
			defer g.endCallback()
			g.Fail(remote, "pipe_create_error")
		},
	}
	if len(peers) == 0 || peers[0] == nil {
		return cfg
	}
	peer := peers[0]
	cfg.NewConnectionCallback = func(conn libplugin.ConnMetadata) error {
		if err := g.Check(conn.RemoteAddr()); err != nil {
			return err
		}
		_, err := peer.Open(context.Background(), conn.UniqueID(), conn.RemoteAddr())
		return err
	}
	count := func(ref *pb.SSHUpstreamConnection, remote string, kind pb.SSHUpstreamFailureKind) bool {
		ctx, cancel := sshcontrol.CallContext(context.Background())
		defer cancel()
		if ref == nil {
			if kind != pb.SSHUpstreamFailureKind_SSH_UPSTREAM_FAILURE_KIND_PIPE_CREATE {
				return false
			}
			// Early failures have a full transport address but no piper UUID.
			// Register an accounting-only identity: without Begin/Acquire it
			// cannot borrow any backend exception. An unavailable/full control
			// service fails closed and is not charged to the client.
			var err error
			ref, err = peer.Open(ctx, "unclassified-"+rand.Text(), remote)
			if err != nil {
				return false
			}
			defer peer.Forget(ref.ConnectionId)
		}
		r, err := peer.Client.ConsumeSSHUpstreamFailure(ctx, &pb.ConsumeSSHUpstreamFailureRequest{Connection: ref, Kind: kind})
		return err == nil && r.GetCountSourceFailure()
	}
	cfg.UpstreamAuthFailureCallback = func(conn libplugin.ConnMetadata, _ string, _ error, _ []string) {
		if count(peer.Find(conn.UniqueID(), conn.RemoteAddr()), conn.RemoteAddr(), pb.SSHUpstreamFailureKind_SSH_UPSTREAM_FAILURE_KIND_AUTH) {
			g.Fail(conn.RemoteAddr(), "auth_failure")
		}
	}
	cfg.PipeCreateErrorCallback = func(remote string, _ error) {
		ref := peer.ByRemote(remote)
		if count(ref, remote, pb.SSHUpstreamFailureKind_SSH_UPSTREAM_FAILURE_KIND_PIPE_CREATE) {
			g.Fail(remote, "pipe_create_error")
		}
		if ref != nil {
			peer.Forget(ref.ConnectionId)
		}
	}
	cfg.PipeStartCallback = func(conn libplugin.ConnMetadata) { peer.Forget(conn.UniqueID()) }
	return cfg
}
