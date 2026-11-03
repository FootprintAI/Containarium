package server

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/app"
	"github.com/footprintai/containarium/internal/events"
	"github.com/footprintai/containarium/pkg/core/container"
	"github.com/footprintai/containarium/pkg/core/incus"
	"github.com/footprintai/containarium/pkg/core/incus/incustest"
)

func TestAwaitWakeEndpoint_OnlyReadyAfterApplicationListens(t *testing.T) {
	// Reserve an ephemeral loopback port, then delay listening to mimic
	// the application startup lag after the Box reports Running.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	release := make(chan struct{})
	listenResult := make(chan error, 1)
	go func() {
		time.Sleep(250 * time.Millisecond)
		srv, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(port))
		listenResult <- err
		if err != nil {
			return
		}
		defer func() { _ = srv.Close() }()
		<-release
	}()
	start := time.Now()
	ip, ready := awaitWakeEndpoint(context.Background(), time.Second, port, func() string { return "127.0.0.1" })
	elapsed := time.Since(start) // Measure the probe, not the listener's lifetime.
	close(release)
	if err := <-listenResult; err != nil {
		t.Fatalf("delayed listener: %v", err)
	}
	if !ready || ip != "127.0.0.1" {
		t.Fatalf("result=(%q,%t) expected ready", ip, ready)
	}
	if elapsed < 230*time.Millisecond {
		t.Fatalf("falsely ready before service booted: elapsed=%v", elapsed)
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

func TestAwaitWakeEndpoint_CancellationInterruptsDial(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan struct{})
	result := make(chan bool, 1)
	go func() {
		_, ready := awaitWakeEndpointWithDial(ctx, 5*time.Second, 443,
			func() string { return "127.0.0.1" },
			func(ctx context.Context, _ string) (net.Conn, error) {
				close(started)
				<-ctx.Done()
				return nil, ctx.Err()
			})
		result <- ready
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("TCP probe did not start")
	}
	cancel()
	select {
	case ready := <-result:
		if ready {
			t.Fatal("cancelled in-flight TCP probe reported ready")
		}
	case <-time.After(300 * time.Millisecond):
		t.Fatal("in-flight TCP probe ignored cancellation")
	}
}

func TestWakeStarter_ProbesTriggeringRouteRatherThanFirstRoute(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	port := listener.Addr().(*net.TCPAddr).Port
	backend := incustest.NewMockBackend()
	backend.Containers["alice-container"] = &incus.ContainerInfo{
		Name:      "alice-container",
		State:     "Stopped",
		IPAddress: "127.0.0.1",
	}
	s := &ContainerServer{
		manager:    container.NewWithBackend(backend),
		emitter:    events.NewEmitter(events.NewBus()),
		routeStore: &fakeRouteLister{routes: []*app.RouteRecord{{TargetPort: 1}, {TargetPort: port}}},
	}
	ready, ip, gotPort, err := NewWakeStarter(s, 1).WakeForRequest(testCtx(), "alice", port)
	if err != nil || !ready || ip != "127.0.0.1" || gotPort != port {
		t.Fatalf("triggering route got ready=%t ip=%q port=%d err=%v", ready, ip, gotPort, err)
	}
}
