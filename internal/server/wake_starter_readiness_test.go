package server

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"
)

func TestAwaitWakeEndpoint_OnlyReadyAfterApplicationListens(t *testing.T) {
	// Reserve an ephemeral loopback port, then delay listening to mimic
	// the systemd service boot lag after an Incus Box reports Running.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		time.Sleep(250 * time.Millisecond)
		srv, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(port))
		if err != nil {
			return
		}
		defer srv.Close()
		time.Sleep(600 * time.Millisecond)
	}()
	start := time.Now()
	ip, ready := awaitWakeEndpoint(context.Background(), time.Second, port, func() string { return "127.0.0.1" })
	<-done
	if !ready || ip != "127.0.0.1" {
		t.Fatalf("result=(%q,%t) expected ready", ip, ready)
	}
	if time.Since(start) < 230*time.Millisecond {
		t.Fatal("falsely ready before service booted")
	}
}

func TestAwaitWakeEndpoint_NoIPNeverReportsReady(t *testing.T) {
	ip, ready := awaitWakeEndpoint(context.Background(), 150*time.Millisecond, 8080, func() string { return "" })
	if ready || ip != "" {
		t.Fatalf("empty live IP must fail closed: %q %t", ip, ready)
	}
}

func TestAwaitWakeEndpoint_CancelledWakeDoesNotReportReady(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	_, ready := awaitWakeEndpoint(ctx, time.Second, 8080, func() string { return "127.0.0.1" })
	if ready || time.Since(start) > 100*time.Millisecond {
		t.Fatal("cancelled wake should fail quickly")
	}
}
