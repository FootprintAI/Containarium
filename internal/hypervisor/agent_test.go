package hypervisor

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// fakeConsole is an in-memory io.ReadWriteCloser standing in for a real
// console socket, so agent tests never touch VirtualBox or the filesystem.
type fakeConsole struct {
	io.Reader
	io.Writer
	closed bool
}

func (f *fakeConsole) Close() error {
	f.closed = true
	return nil
}

// fakeProvider hands out a fixed console (or error) regardless of target,
// recording what target it was asked to open.
type fakeProvider struct {
	console      *fakeConsole
	err          error
	lastTarget   string
	openCalled   bool
	openCanceled bool
}

func (p *fakeProvider) OpenConsole(ctx context.Context, target string) (io.ReadWriteCloser, error) {
	p.openCalled = true
	p.lastTarget = target
	if ctx.Err() != nil {
		p.openCanceled = true
	}
	if p.err != nil {
		return nil, p.err
	}
	return p.console, nil
}

func writeHandshakeLine(t *testing.T, conn net.Conn, req handshakeRequest) {
	t.Helper()
	b, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("failed to marshal handshake: %v", err)
	}
	if _, err := conn.Write(append(b, '\n')); err != nil {
		t.Fatalf("failed to write handshake: %v", err)
	}
}

func TestAgent_HandleConn_Success(t *testing.T) {
	server, client := net.Pipe()
	defer func() { _ = client.Close() }()

	consoleReader, testWriter := io.Pipe()
	console := &fakeConsole{Reader: consoleReader, Writer: io.Discard}
	provider := &fakeProvider{console: console}

	agent := &Agent{Token: "secret", Provider: provider}
	done := make(chan struct{})
	go func() {
		agent.HandleConn(context.Background(), server)
		close(done)
	}()

	writeHandshakeLine(t, client, handshakeRequest{Token: "secret", Target: "containarium-byoc-1"})

	reader := bufio.NewReader(client)
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("failed to read response: %v", err)
	}
	if strings.TrimSpace(line) != "ok" {
		t.Fatalf("got %q, want \"ok\"", line)
	}

	// Prove the connection is now a raw relay to the console: bytes written
	// into the console's read side arrive at the client.
	go func() { _, _ = testWriter.Write([]byte("boot log line\n")); _ = testWriter.Close() }()
	relayed, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("failed to read relayed console output: %v", err)
	}
	if relayed != "boot log line\n" {
		t.Fatalf("got %q, want %q", relayed, "boot log line\n")
	}

	if provider.lastTarget != "containarium-byoc-1" {
		t.Fatalf("provider opened target %q, want %q", provider.lastTarget, "containarium-byoc-1")
	}

	_ = client.Close()
	<-done

	if !console.closed {
		t.Fatal("expected the console to be closed once the session ended")
	}
}

func TestAgent_HandleConn_WrongToken(t *testing.T) {
	server, client := net.Pipe()
	defer func() { _ = client.Close() }()

	provider := &fakeProvider{console: &fakeConsole{Reader: strings.NewReader(""), Writer: io.Discard}}
	agent := &Agent{Token: "secret", Provider: provider}
	done := make(chan struct{})
	go func() {
		agent.HandleConn(context.Background(), server)
		close(done)
	}()

	writeHandshakeLine(t, client, handshakeRequest{Token: "wrong", Target: "containarium-byoc-1"})

	reader := bufio.NewReader(client)
	line, _ := reader.ReadString('\n')
	if !strings.HasPrefix(line, "error:") {
		t.Fatalf("got %q, want an error response", line)
	}
	<-done

	if provider.openCalled {
		t.Fatal("provider should never be consulted for an unauthorized request")
	}
}

func TestAgent_HandleConn_EmptyAgentTokenAuthorizesNothing(t *testing.T) {
	server, client := net.Pipe()
	defer func() { _ = client.Close() }()

	provider := &fakeProvider{console: &fakeConsole{Reader: strings.NewReader(""), Writer: io.Discard}}
	agent := &Agent{Token: "", Provider: provider} // misconfigured: no token set
	done := make(chan struct{})
	go func() {
		agent.HandleConn(context.Background(), server)
		close(done)
	}()

	// Even an empty presented token must not match an empty Agent.Token.
	writeHandshakeLine(t, client, handshakeRequest{Token: "", Target: "containarium-byoc-1"})

	reader := bufio.NewReader(client)
	line, _ := reader.ReadString('\n')
	if !strings.HasPrefix(line, "error:") {
		t.Fatalf("got %q, want an error response", line)
	}
	<-done

	if provider.openCalled {
		t.Fatal("an unconfigured Agent.Token must never authorize a request")
	}
}

func TestAgent_HandleConn_MissingTarget(t *testing.T) {
	server, client := net.Pipe()
	defer func() { _ = client.Close() }()

	provider := &fakeProvider{}
	agent := &Agent{Token: "secret", Provider: provider}
	done := make(chan struct{})
	go func() {
		agent.HandleConn(context.Background(), server)
		close(done)
	}()

	writeHandshakeLine(t, client, handshakeRequest{Token: "secret", Target: ""})

	reader := bufio.NewReader(client)
	line, _ := reader.ReadString('\n')
	if !strings.HasPrefix(line, "error:") {
		t.Fatalf("got %q, want an error response", line)
	}
	<-done

	if provider.openCalled {
		t.Fatal("provider should never be consulted for a request with no target")
	}
}

func TestAgent_HandleConn_ProviderError(t *testing.T) {
	server, client := net.Pipe()
	defer func() { _ = client.Close() }()

	provider := &fakeProvider{err: errors.New("no such guest")}
	agent := &Agent{Token: "secret", Provider: provider}
	done := make(chan struct{})
	go func() {
		agent.HandleConn(context.Background(), server)
		close(done)
	}()

	writeHandshakeLine(t, client, handshakeRequest{Token: "secret", Target: "ghost"})

	reader := bufio.NewReader(client)
	line, _ := reader.ReadString('\n')
	if !strings.Contains(line, "no such guest") {
		t.Fatalf("got %q, want it to surface the provider's error", line)
	}
	<-done
}

func TestAgent_HandleConn_MalformedHandshake(t *testing.T) {
	server, client := net.Pipe()
	defer func() { _ = client.Close() }()

	provider := &fakeProvider{}
	agent := &Agent{Token: "secret", Provider: provider}
	done := make(chan struct{})
	go func() {
		agent.HandleConn(context.Background(), server)
		close(done)
	}()

	if _, err := client.Write([]byte("not json\n")); err != nil {
		t.Fatalf("write failed: %v", err)
	}

	reader := bufio.NewReader(client)
	line, _ := reader.ReadString('\n')
	if !strings.HasPrefix(line, "error:") {
		t.Fatalf("got %q, want an error response", line)
	}
	<-done

	if provider.openCalled {
		t.Fatal("provider should never be consulted for a malformed handshake")
	}
}

func TestAgent_HandleConn_NoProviderConfigured(t *testing.T) {
	server, client := net.Pipe()
	defer func() { _ = client.Close() }()

	agent := &Agent{Token: "secret"} // Provider left nil
	done := make(chan struct{})
	go func() {
		agent.HandleConn(context.Background(), server)
		close(done)
	}()

	writeHandshakeLine(t, client, handshakeRequest{Token: "secret", Target: "containarium-byoc-1"})

	reader := bufio.NewReader(client)
	line, _ := reader.ReadString('\n')
	if !strings.HasPrefix(line, "error:") {
		t.Fatalf("got %q, want an error response", line)
	}
	<-done
}

// TestAgent_HandleConn_NoOverreadPastHandshake is a regression test: a
// bufio.Reader-based implementation of readHandshake would silently
// swallow bytes the caller sends immediately after the handshake line
// (without waiting for the "ok" response) into its own internal buffer,
// which relay() never sees since it reads directly off the raw conn. This
// sends the handshake and a follow-up console-input chunk in a SINGLE
// Write call — reproducing them arriving in one underlying read — and
// asserts the follow-up bytes still reach the console.
func TestAgent_HandleConn_NoOverreadPastHandshake(t *testing.T) {
	server, client := net.Pipe()
	defer func() { _ = client.Close() }()

	consoleInputR, consoleInputW := io.Pipe()
	console := &fakeConsole{Reader: strings.NewReader(""), Writer: consoleInputW}
	provider := &fakeProvider{console: console}

	agent := &Agent{Token: "secret", Provider: provider}
	done := make(chan struct{})
	go func() {
		agent.HandleConn(context.Background(), server)
		close(done)
	}()

	hs, err := json.Marshal(handshakeRequest{Token: "secret", Target: "containarium-byoc-1"})
	if err != nil {
		t.Fatalf("failed to marshal handshake: %v", err)
	}
	// One Write, handshake + follow-up console input together — the
	// scenario a real socket read can coalesce.
	payload := append(append(hs, '\n'), []byte("boot-time keypress")...)
	writeDone := make(chan struct{})
	go func() {
		if _, err := client.Write(payload); err != nil {
			t.Errorf("write failed: %v", err)
		}
		close(writeDone)
	}()

	reader := bufio.NewReader(client)
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("failed to read response: %v", err)
	}
	if strings.TrimSpace(line) != "ok" {
		t.Fatalf("got %q, want \"ok\"", line)
	}

	got := make([]byte, len("boot-time keypress"))
	if _, err := io.ReadFull(consoleInputR, got); err != nil {
		t.Fatalf("follow-up bytes never reached the console (over-read bug): %v", err)
	}
	if string(got) != "boot-time keypress" {
		t.Fatalf("got %q, want %q", got, "boot-time keypress")
	}

	<-writeDone
	_ = client.Close()
	<-done
}

func TestTokenAuthorized(t *testing.T) {
	cases := []struct {
		name      string
		expected  string
		presented string
		want      bool
	}{
		{"matching", "secret", "secret", true},
		{"mismatched", "secret", "wrong", false},
		{"both empty", "", "", false},
		{"expected empty, presented set", "", "secret", false},
		{"expected set, presented empty", "secret", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := tokenAuthorized(c.expected, c.presented); got != c.want {
				t.Errorf("tokenAuthorized(%q, %q) = %v, want %v", c.expected, c.presented, got, c.want)
			}
		})
	}
}

func TestReadHandshake_RejectsOversizeLine(t *testing.T) {
	huge := strings.NewReader(fmt.Sprintf(`{"token":"%s","target":"x"}`+"\n", strings.Repeat("a", 100)))
	if _, err := readHandshake(huge, 16); err == nil {
		t.Fatal("expected an error for a handshake line exceeding maxLine")
	}
}

func TestAgent_Serve_StopsOnContextCancel(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	agent := &Agent{Token: "secret", Provider: &fakeProvider{}}

	serveErr := make(chan error, 1)
	go func() { serveErr <- agent.Serve(ctx, ln) }()

	cancel()
	_ = ln.Close() // unblock Accept

	select {
	case err := <-serveErr:
		if err != nil {
			t.Fatalf("expected a nil error on clean shutdown, got: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not return after context cancellation")
	}
}
