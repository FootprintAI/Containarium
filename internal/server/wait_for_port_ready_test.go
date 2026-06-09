package server

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestWaitForPortReady(t *testing.T) {
	ctx := context.Background()

	// A listening port → becomes ready immediately (returns false = not timed out).
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	addr := ln.Addr().(*net.TCPAddr)
	if waitForPortReady(ctx, "127.0.0.1", addr.Port, time.Second) {
		t.Error("listening port: expected ready (false), got timed-out (true)")
	}

	// A closed port → times out (returns true).
	closedLn, _ := net.Listen("tcp", "127.0.0.1:0")
	closedPort := closedLn.Addr().(*net.TCPAddr).Port
	_ = closedLn.Close()
	if !waitForPortReady(ctx, "127.0.0.1", closedPort, 300*time.Millisecond) {
		t.Error("closed port: expected timed-out (true), got ready (false)")
	}

	// Empty IP / non-positive port short-circuit to "ready" (false).
	if waitForPortReady(ctx, "", 22, time.Second) {
		t.Error("empty ip: expected short-circuit ready (false)")
	}
	if waitForPortReady(ctx, "127.0.0.1", 0, time.Second) {
		t.Error("zero port: expected short-circuit ready (false)")
	}
}
