package sentinel

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"github.com/hashicorp/yamux"
)

// TunnelClient connects from a (firewalled) spot VM outbound to the sentinel
// and serves port-forwarding requests over a yamux session.
type TunnelClient struct {
	SentinelAddr string
	Token        string
	SpotID       string
	Ports        []int
}

// Run connects to the sentinel and serves tunnel traffic.
// It reconnects with exponential backoff on failure. Blocks until ctx is cancelled.
func (tc *TunnelClient) Run(ctx context.Context) error {
	backoff := time.Second
	maxBackoff := 60 * time.Second

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		err := tc.connectAndServe(ctx)
		if err != nil {
			log.Printf("[tunnel-client] connection lost: %v", err)
		}

		select {
		case <-ctx.Done():
			return nil
		case <-time.After(backoff):
		}

		backoff = backoff * 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
		log.Printf("[tunnel-client] reconnecting to %s (backoff: %s)...", tc.SentinelAddr, backoff)
	}
}

func (tc *TunnelClient) connectAndServe(ctx context.Context) error {
	// Connect to sentinel
	dialer := net.Dialer{Timeout: 15 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", tc.SentinelAddr)
	if err != nil {
		return fmt.Errorf("dial sentinel %s: %w", tc.SentinelAddr, err)
	}
	defer conn.Close()

	log.Printf("[tunnel-client] connected to sentinel %s", tc.SentinelAddr)

	// Send handshake
	hs := &TunnelHandshake{
		Token:  tc.Token,
		SpotID: tc.SpotID,
		Ports:  tc.Ports,
	}
	if err := writeHandshake(conn, hs); err != nil {
		return fmt.Errorf("write handshake: %w", err)
	}

	// Read response
	resp, err := readHandshakeResponse(conn)
	if err != nil {
		return fmt.Errorf("read handshake response: %w", err)
	}
	if !resp.OK {
		return fmt.Errorf("handshake rejected: %s", resp.Error)
	}

	log.Printf("[tunnel-client] registered as %q, assigned IP %s", tc.SpotID, resp.AssignedIP)

	// Create yamux session. The spot is the yamux *server* (accepts streams
	// from sentinel), even though the spot initiated the TCP connection.
	yamuxCfg := yamux.DefaultConfig()
	yamuxCfg.EnableKeepAlive = true
	yamuxCfg.KeepAliveInterval = 15 * time.Second
	yamuxCfg.ConnectionWriteTimeout = 10 * time.Second

	session, err := yamux.Server(conn, yamuxCfg)
	if err != nil {
		return fmt.Errorf("yamux server init: %w", err)
	}

	// Close session when context is cancelled (enables clean shutdown)
	go func() {
		<-ctx.Done()
		session.Close()
	}()
	defer session.Close()

	log.Printf("[tunnel-client] yamux session established, serving port forwards")

	// Accept streams from sentinel and proxy to local ports
	return tc.serveStreams(ctx, session)
}

// serveStreams accepts yamux streams from the sentinel and proxies each one
// to the appropriate local port.
func (tc *TunnelClient) serveStreams(ctx context.Context, session *yamux.Session) error {
	for {
		stream, err := session.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				return fmt.Errorf("yamux accept: %w", err)
			}
		}
		go tc.handleStream(stream)
	}
}

// handleStream reads the 2-byte port header from a yamux stream,
// then proxies bidirectionally to the local port.
func (tc *TunnelClient) handleStream(stream net.Conn) {
	defer stream.Close()

	// Read 2-byte port header (big-endian)
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(stream, portBuf); err != nil {
		log.Printf("[tunnel-client] failed to read port header: %v", err)
		return
	}
	port := int(portBuf[0])<<8 | int(portBuf[1])

	// Connect to the local service on that port
	localAddr := fmt.Sprintf("127.0.0.1:%d", port)
	localConn, err := net.DialTimeout("tcp", localAddr, 5*time.Second)
	if err != nil {
		log.Printf("[tunnel-client] failed to connect to local %s: %v", localAddr, err)
		return
	}
	defer localConn.Close()

	// Bidirectional copy — when one direction finishes, close both sides
	done := make(chan struct{}, 2)
	go func() {
		io.Copy(localConn, stream)
		// Close write side of local conn to signal EOF
		if tc, ok := localConn.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
		done <- struct{}{}
	}()
	go func() {
		io.Copy(stream, localConn)
		// Close write side of stream to signal EOF
		if cs, ok := stream.(interface{ CloseWrite() error }); ok {
			cs.CloseWrite()
		}
		done <- struct{}{}
	}()
	// Wait for first direction to finish, then close both
	<-done
}
