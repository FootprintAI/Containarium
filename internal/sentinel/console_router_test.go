package sentinel

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConsoleRouterPolicy_Validate(t *testing.T) {
	cases := []struct {
		name      string
		configure string
		presented string
		wantErr   bool
	}{
		{"matching", "secret", "secret", false},
		{"mismatched", "secret", "wrong", true},
		{"unconfigured policy", "", "secret", true},
		{"empty presented", "secret", "", true},
		{"both empty", "", "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := NewConsoleRouterPolicy(c.configure)
			err := p.Validate(c.presented)
			if c.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestConsoleRouterIntegration exercises the full path a real console
// request takes: a caller dials the router, presents the router's own
// coarse-grained token plus a spot/port, the router calls
// TunnelRegistry.DialTunnel exactly like the SNI router and sshpiper
// already do for :443/:22, and the connection becomes a raw relay to
// whatever is listening on that advertised port — standing in here for
// the hypervisor-agent's own Agent.Serve (internal/hypervisor), which has
// its own handshake and auth one hop further in.
func TestConsoleRouterIntegration(t *testing.T) {
	withRecordedAliases(t)
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tunnelToken := "tunnel-integration-token"
	routerToken := "console-router-token"

	// Stand in for the hypervisor-agent's console listener: an echo server
	// on the "spot" side, reached by the same port-forward mechanism any
	// other tunnel-advertised service already uses.
	hvConsolePort := freePort(t)
	hvLn, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", hvConsolePort))
	require.NoError(t, err)
	defer func() { _ = hvLn.Close() }()
	go func() {
		for {
			conn, err := hvLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				buf := make([]byte, 4096)
				for {
					n, err := c.Read(buf)
					if n > 0 {
						if _, werr := c.Write(buf[:n]); werr != nil {
							return
						}
					}
					if err != nil {
						return
					}
				}
			}(conn)
		}
	}()

	// Sentinel side: ConnMux for the tunnel + TunnelServer + registry.
	muxPort := freePort(t)
	muxLn, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", muxPort))
	require.NoError(t, err)

	connMux := NewConnMuxFromListener(muxLn)
	go connMux.Run()
	defer func() { _ = connMux.Close() }()

	registry := NewTunnelRegistry()
	tunnelServer := NewTunnelServer("", policyAny(tunnelToken), registry, 0)

	connectCh := make(chan *TunnelSpot, 1)
	tunnelServer.OnConnect = func(spot *TunnelSpot) {
		select {
		case connectCh <- spot:
		default:
		}
	}

	go func() { _ = tunnelServer.Serve(ctx, connMux.TunnelListener()) }()
	time.Sleep(100 * time.Millisecond)

	// The hypervisor host's tunnel client — reused completely unmodified,
	// exactly as internal/cmd/hypervisor_agent.go does in production.
	client := &TunnelClient{
		SentinelAddr: fmt.Sprintf("127.0.0.1:%d", muxPort),
		Token:        tunnelToken,
		SpotID:       "lab-vbox-host-1",
		Ports:        []int{hvConsolePort},
	}
	go func() { _ = client.Run(ctx) }()

	select {
	case <-connectCh:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for tunnel connection")
	}
	time.Sleep(200 * time.Millisecond)

	// The console router itself, under test.
	routerPort := freePort(t)
	router := NewConsoleRouter(fmt.Sprintf("127.0.0.1:%d", routerPort), NewConsoleRouterPolicy(routerToken), registry)
	go func() { _ = router.Run(ctx) }()
	time.Sleep(100 * time.Millisecond)

	dial := func(t *testing.T) net.Conn {
		t.Helper()
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", routerPort), 3*time.Second)
		require.NoError(t, err)
		return conn
	}

	t.Run("wrong router token is rejected", func(t *testing.T) {
		conn := dial(t)
		defer func() { _ = conn.Close() }()

		require.NoError(t, json.NewEncoder(conn).Encode(ConsoleRouterHandshake{
			Token: "wrong", SpotID: "lab-vbox-host-1", Port: hvConsolePort,
		}))
		var resp ConsoleRouterResponse
		_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		require.NoError(t, json.NewDecoder(conn).Decode(&resp))
		assert.False(t, resp.OK)
	})

	t.Run("unknown spot is rejected", func(t *testing.T) {
		conn := dial(t)
		defer func() { _ = conn.Close() }()

		require.NoError(t, json.NewEncoder(conn).Encode(ConsoleRouterHandshake{
			Token: routerToken, SpotID: "no-such-hypervisor", Port: hvConsolePort,
		}))
		var resp ConsoleRouterResponse
		_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		require.NoError(t, json.NewDecoder(conn).Decode(&resp))
		assert.False(t, resp.OK)
	})

	t.Run("valid request relays end to end", func(t *testing.T) {
		conn := dial(t)
		defer func() { _ = conn.Close() }()

		require.NoError(t, json.NewEncoder(conn).Encode(ConsoleRouterHandshake{
			Token: routerToken, SpotID: "lab-vbox-host-1", Port: hvConsolePort,
		}))

		reader := bufio.NewReader(conn)
		respLine, err := reader.ReadString('\n')
		require.NoError(t, err)
		var resp ConsoleRouterResponse
		require.NoError(t, json.Unmarshal([]byte(respLine), &resp))
		require.True(t, resp.OK, "response: %+v", resp)

		// From here the connection is a raw relay to the echo listener
		// standing in for the hypervisor-agent.
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		_, err = conn.Write([]byte("hello from operator"))
		require.NoError(t, err)

		buf := make([]byte, len("hello from operator"))
		_, err = fullRead(reader, buf)
		require.NoError(t, err)
		assert.Equal(t, "hello from operator", string(buf))
	})
}

// fullRead reads exactly len(buf) bytes from r, since bufio.Reader may
// already hold some of them buffered from the handshake response line.
func fullRead(r *bufio.Reader, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := r.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}
