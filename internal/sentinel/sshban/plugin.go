package sshban

import (
	"context"
	"errors"
	"fmt"

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
func (g *Guard) PluginConfig() libplugin.SshPiperPluginConfig {
	return libplugin.SshPiperPluginConfig{
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
}
