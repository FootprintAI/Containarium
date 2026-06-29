package sentinel

import (
	"io"
	"log"
	"net"
	"sync"
	"time"
)

// ConnMux multiplexes a single TCP listener into tunnel and HTTPS connections
// based on the first byte of each connection.
//
// Tunnel handshakes start with '{' (JSON), while TLS/HTTPS starts with 0x16
// (TLS record layer). All non-tunnel connections are routed to HTTPS handling.
//
// This allows the tunnel and HTTPS to share port 443, avoiding the need to
// open an extra port on the sentinel's firewall.
type ConnMux struct {
	listener net.Listener

	// Channel-based listeners that consumers Accept() from
	tunnelLn *chanListener
	httpsLn  *chanListener
}

// NewConnMux creates a multiplexer on the given address (e.g., ":443").
func NewConnMux(addr string) (*ConnMux, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	return NewConnMuxFromListener(ln), nil
}

// NewConnMuxFromListener creates a multiplexer from an existing listener.
func NewConnMuxFromListener(ln net.Listener) *ConnMux {
	return &ConnMux{
		listener: ln,
		tunnelLn: newChanListener(ln.Addr()),
		httpsLn:  newChanListener(ln.Addr()),
	}
}

// TunnelListener returns a net.Listener that yields only tunnel connections
// (those whose first byte is '{').
func (cm *ConnMux) TunnelListener() net.Listener {
	return cm.tunnelLn
}

// HTTPSListener returns a net.Listener that yields all non-tunnel connections.
func (cm *ConnMux) HTTPSListener() net.Listener {
	return cm.httpsLn
}

// HTTPSChanListener returns the underlying chanListener for HTTPS.
// Used by Manager to create a dispatchListener for swapping consumers.
func (cm *ConnMux) HTTPSChanListener() *chanListener {
	return cm.httpsLn
}

// Run accepts connections and routes them. Blocks until the listener is closed.
func (cm *ConnMux) Run() {
	log.Printf("[conn-mux] multiplexing on %s (tunnel + HTTPS)", cm.listener.Addr())
	for {
		conn, err := cm.listener.Accept()
		if err != nil {
			// Listener closed
			_ = cm.tunnelLn.Close()
			_ = cm.httpsLn.Close()
			return
		}
		go cm.route(conn)
	}
}

// Close closes the underlying listener and both channel listeners.
func (cm *ConnMux) Close() error {
	_ = cm.tunnelLn.Close()
	_ = cm.httpsLn.Close()
	return cm.listener.Close()
}

func (cm *ConnMux) route(conn net.Conn) {
	// Peek the first byte with a short deadline
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 1)
	n, err := conn.Read(buf)
	_ = conn.SetReadDeadline(time.Time{}) // clear deadline

	if err != nil || n == 0 {
		_ = conn.Close()
		return
	}

	// Wrap the connection so the peeked byte is replayed to the consumer
	peeked := &peekedConn{Conn: conn, peeked: buf[:n]}

	if buf[0] == '{' {
		// Tunnel handshake (JSON)
		cm.tunnelLn.Enqueue(peeked)
	} else {
		// TLS/HTTPS (or any other protocol)
		cm.httpsLn.Enqueue(peeked)
	}
}

// peekedConn wraps a net.Conn and replays peeked bytes before reading from
// the underlying connection.
type peekedConn struct {
	net.Conn
	peeked []byte
	offset int
}

func (pc *peekedConn) Read(b []byte) (int, error) {
	if pc.offset < len(pc.peeked) {
		n := copy(b, pc.peeked[pc.offset:])
		pc.offset += n
		return n, nil
	}
	return pc.Conn.Read(b)
}

// chanListener implements net.Listener using a channel of connections.
// This allows routing connections from the ConnMux to different consumers
// (tunnel server, HTTPS proxy, maintenance server) that expect a net.Listener.
type chanListener struct {
	ch     chan net.Conn
	addr   net.Addr
	closed chan struct{}
	once   sync.Once
}

func newChanListener(addr net.Addr) *chanListener {
	return &chanListener{
		ch:     make(chan net.Conn, 64),
		addr:   addr,
		closed: make(chan struct{}),
	}
}

func (cl *chanListener) Accept() (net.Conn, error) {
	select {
	case conn, ok := <-cl.ch:
		if !ok {
			return nil, net.ErrClosed
		}
		return conn, nil
	case <-cl.closed:
		return nil, net.ErrClosed
	}
}

func (cl *chanListener) Close() error {
	cl.once.Do(func() {
		close(cl.closed)
	})
	return nil
}

func (cl *chanListener) Addr() net.Addr {
	return cl.addr
}

// Enqueue sends a connection to the listener's channel.
// If the channel is full or the listener is closed, the connection is dropped.
func (cl *chanListener) Enqueue(conn net.Conn) {
	select {
	case cl.ch <- conn:
	case <-cl.closed:
		_ = conn.Close()
	}
}

// dispatchListener wraps a chanListener with a dispatch mechanism.
// Connections from the inner listener are sent to whichever consumer
// is currently registered via SetHandler. This allows swapping between
// maintenance server and HTTPS proxy without closing the shared listener.
type dispatchListener struct {
	inner   *chanListener
	mu      sync.RWMutex
	handler func(net.Conn) // current connection handler
}

func newDispatchListener(inner *chanListener) *dispatchListener {
	dl := &dispatchListener{inner: inner}
	// Start a goroutine that pulls from the chanListener and dispatches
	go dl.dispatch()
	return dl
}

func (dl *dispatchListener) dispatch() {
	for {
		conn, err := dl.inner.Accept()
		if err != nil {
			return
		}
		dl.mu.RLock()
		h := dl.handler
		dl.mu.RUnlock()
		if h != nil {
			go h(conn)
		} else {
			_ = conn.Close()
		}
	}
}

// SetHandler sets the function that handles incoming HTTPS connections.
func (dl *dispatchListener) SetHandler(h func(net.Conn)) {
	dl.mu.Lock()
	dl.handler = h
	dl.mu.Unlock()
}

// HTTPSProxy proxies connections from a listener to a target address.
// Used in proxy mode to forward HTTPS traffic from the ConnMux to the spot VM.
type HTTPSProxy struct {
	target string // e.g., "127.0.0.2:443" or "10.x.x.x:443"
}

// Serve accepts connections from ln and proxies them to the target.
// Blocks until ln is closed.
func (hp *HTTPSProxy) Serve(ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go hp.proxy(conn)
	}
}

func (hp *HTTPSProxy) proxy(src net.Conn) {
	defer func() { _ = src.Close() }()

	dst, err := sentinelDialer.Dial("tcp", hp.target)
	if err != nil {
		log.Printf("[https-proxy] failed to connect to %s: %v", hp.target, err)
		return
	}
	defer func() { _ = dst.Close() }()

	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(dst, src); done <- struct{}{} }()
	go func() { _, _ = io.Copy(src, dst); done <- struct{}{} }()
	<-done
}
