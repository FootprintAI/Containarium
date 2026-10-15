//go:build !windows && !containarium_client

package cmd

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/tg123/sshpiper/libplugin"
	"github.com/tg123/sshpiper/libplugin/ioconn"
	"google.golang.org/grpc"
)

// exitingRoutingChild serves a real bootstrap response before terminating.
type exitingRoutingChild struct {
	libplugin.UnimplementedSshPiperPluginServer
}

// ListCallbacks makes a later child exit distinguishable from failed bootstrap.
func (exitingRoutingChild) ListCallbacks(context.Context, *libplugin.ListCallbackRequest) (*libplugin.ListCallbackResponse, error) {
	time.AfterFunc(100*time.Millisecond, func() { os.Exit(23) })
	return &libplugin.ListCallbackResponse{}, nil
}

// TestSSHUpstreamCrashChildProcess is the disposable routing subprocess; it
// exits directly so test-runner output cannot corrupt its stdio protocol.
func TestSSHUpstreamCrashChildProcess(t *testing.T) {
	if os.Getenv("CONTAINARIUM_UPSTREAM_COMMAND_TEST") != "1" {
		return
	}
	l, err := ioconn.ListenFromSingleIO(os.Stdin, os.Stdout)
	if err != nil {
		os.Exit(2)
	}
	server := grpc.NewServer()
	libplugin.RegisterSshPiperPluginServer(server, exitingRoutingChild{})
	_ = server.Serve(l)
	os.Exit(3)
}

// TestSSHUpstreamCommandProcess isolates NewFromStdio's global stdout mutation
// from the unit-test process while exercising the production command lifecycle.
func TestSSHUpstreamCommandProcess(t *testing.T) {
	if os.Getenv("CONTAINARIUM_UPSTREAM_COMMAND_TEST") != "1" {
		return
	}
	binary, err := os.Executable()
	if err != nil {
		os.Exit(2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	command := newSSHUpstreamPluginCommand()
	command.SetArgs([]string{"--plugin", binary, "--plugin-arg=-test.run=^TestSSHUpstreamCrashChildProcess$"})
	err = command.ExecuteContext(ctx)
	if err == nil || !strings.Contains(err.Error(), "routing child exited") {
		fmt.Fprintf(os.Stderr, "supervisor missed child exit: %v\n", err)
		os.Exit(1)
	}
	os.Exit(0)
}

// TestSSHUpstreamPluginStopsWhenRoutingChildExits ensures systemd/sshpiperd can
// restart a failed chain instead of retaining an adapter with a dead router.
func TestSSHUpstreamPluginStopsWhenRoutingChildExits(t *testing.T) {
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	child := exec.CommandContext(ctx, binary, "-test.run=^TestSSHUpstreamCommandProcess$")
	child.Env = append(os.Environ(), "CONTAINARIUM_UPSTREAM_COMMAND_TEST=1")
	if out, err := child.CombinedOutput(); err != nil {
		t.Fatalf("adapter did not stop after routing child exit: %v\n%q", err, out)
	}
}
