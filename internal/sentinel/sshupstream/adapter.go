// Package sshupstream exposes the sentinel's selected-routing transport hook.
package sshupstream

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/tg123/sshpiper/libplugin"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
	"google.golang.org/protobuf/proto"
)

// Attempt ties one selected upstream to its originating transport connection.
type Attempt struct {
	ID, ConnectionID, RemoteAddr, URI string
}

// Dial opens the selected upstream without making an authorization decision.
type Dial func(context.Context, Attempt) (net.Conn, error)

// binding is a one-use capability created only after the child selects a route.
type binding struct {
	attempt Attempt
	expires time.Time
	host    string
	keys    []byte
	verify  ssh.HostKeyCallback
	conn    net.Conn
}

// adapter owns bounded capabilities, never the child's authorization policy.
type adapter struct {
	ctx           context.Context
	dial          Dial
	mu            sync.Mutex
	bindings      map[string]binding
	setups        map[string]binding
	childVerifier bool
}

// NewAdapter wraps the pinned routing contract and adds an attempt-correlated
// transport callback. Unknown child capabilities fail closed at startup.
func NewAdapter(ctx context.Context, child libplugin.SshPiperPluginClient, dial Dial) (libplugin.SshPiperPluginConfig, error) {
	cfg := libplugin.SshPiperPluginConfig{}
	if child == nil || dial == nil {
		return cfg, fmt.Errorf("router and transport dialer are required")
	}
	bootstrap, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	listed, err := child.ListCallbacks(bootstrap, &libplugin.ListCallbackRequest{})
	if err != nil {
		return cfg, err
	}
	caps := map[string]bool{}
	for _, name := range listed.GetCallbacks() {
		switch name {
		case "NewConnection", "NextAuthMethods", "NoneAuth", "PasswordAuth", "PublicKeyAuth", "KeyboardInteractiveAuth", "UpstreamAuthFailure", "Banner", "VerifyHostKey", "PipeCreateError", "PipeStart", "PipeError":
			caps[name] = true
		default:
			return cfg, fmt.Errorf("unsupported child routing capability %q", name)
		}
	}
	a := &adapter{ctx: ctx, dial: dial, bindings: make(map[string]binding), setups: make(map[string]binding), childVerifier: caps["VerifyHostKey"]}
	cfg.CreateConnCallback = a.connect
	if caps["NewConnection"] {
		cfg.NewConnectionCallback = func(c libplugin.ConnMetadata) error {
			_, err := child.NewConnection(ctx, &libplugin.NewConnectionRequest{Meta: metadata(c)})
			return err
		}
	}
	if caps["NextAuthMethods"] {
		cfg.NextAuthMethodsCallback = func(c libplugin.ConnMetadata) ([]string, error) {
			r, err := child.NextAuthMethods(ctx, &libplugin.NextAuthMethodsRequest{Meta: metadata(c)})
			if err != nil {
				return nil, err
			}
			out := make([]string, 0, len(r.GetMethods()))
			for _, m := range r.GetMethods() {
				name := libplugin.AuthMethodTypeToName(m)
				if name == "" {
					return nil, fmt.Errorf("unsupported child auth method %v", m)
				}
				out = append(out, name)
			}
			return out, nil
		}
	}
	if caps["NoneAuth"] {
		cfg.NoClientAuthCallback = func(c libplugin.ConnMetadata) (*libplugin.Upstream, error) {
			r, err := child.NoneAuth(ctx, &libplugin.NoneAuthRequest{Meta: metadata(c)})
			if err != nil {
				return nil, err
			}
			return a.bind(c, r.GetUpstream())
		}
	}
	if caps["PublicKeyAuth"] {
		cfg.PublicKeyCallback = func(c libplugin.ConnMetadata, key []byte) (*libplugin.Upstream, error) {
			r, err := child.PublicKeyAuth(ctx, &libplugin.PublicKeyAuthRequest{Meta: metadata(c), PublicKey: key})
			if err != nil {
				return nil, err
			}
			return a.bind(c, r.GetUpstream())
		}
	}
	if caps["PasswordAuth"] {
		cfg.PasswordCallback = func(c libplugin.ConnMetadata, password []byte) (*libplugin.Upstream, error) {
			r, err := child.PasswordAuth(ctx, &libplugin.PasswordAuthRequest{Meta: metadata(c), Password: password})
			if err != nil {
				return nil, err
			}
			return a.bind(c, r.GetUpstream())
		}
	}
	if caps["KeyboardInteractiveAuth"] {
		cfg.KeyboardInteractiveCallback = func(c libplugin.ConnMetadata, challenge libplugin.KeyboardInteractiveChallenge) (*libplugin.Upstream, error) {
			stream, err := child.KeyboardInteractiveAuth(ctx)
			if err != nil {
				return nil, err
			}
			defer func() { _ = stream.CloseSend() }()
			for {
				m, err := stream.Recv()
				if err != nil {
					return nil, err
				}
				switch {
				case m.GetMetaRequest() != nil:
					err = stream.Send(&libplugin.KeyboardInteractiveAuthMessage{Message: &libplugin.KeyboardInteractiveAuthMessage_MetaResponse{MetaResponse: &libplugin.KeyboardInteractiveMetaResponse{Meta: metadata(c)}}})
				case m.GetPromptRequest() != nil:
					p := m.GetPromptRequest()
					answers := make([]string, 0, len(p.Questions))
					if len(p.Questions) == 0 {
						_, err = challenge(p.Name, p.Instruction, "", false)
					}
					for _, q := range p.Questions {
						var answer string
						answer, err = challenge(p.Name, p.Instruction, q.Text, q.Echo)
						if err != nil {
							break
						}
						answers = append(answers, answer)
					}
					if err == nil && len(p.Questions) > 0 {
						err = stream.Send(&libplugin.KeyboardInteractiveAuthMessage{Message: &libplugin.KeyboardInteractiveAuthMessage_UserResponse{UserResponse: &libplugin.KeyboardInteractiveUserResponse{Answers: answers}}})
					}
				case m.GetFinishRequest() != nil:
					return a.bind(c, m.GetFinishRequest().GetUpstream())
				default:
					return nil, fmt.Errorf("unexpected child keyboard-interactive message")
				}
				if err != nil {
					return nil, err
				}
			}
		}
	}
	if caps["Banner"] {
		cfg.BannerCallback = func(c libplugin.ConnMetadata) string {
			r, err := child.Banner(ctx, &libplugin.BannerRequest{Meta: metadata(c)})
			if err != nil {
				return ""
			}
			return r.GetMessage()
		}
	}
	// ConnOverGrpc reports a URI as RemoteAddr; restore the selected endpoint
	// and actual socket identity before either existing verification path.
	cfg.VerifyHostKeyCallback = func(c libplugin.ConnMetadata, hostname, _ string, key []byte) error {
		a.mu.Lock()
		b, ok := a.setups[c.UniqueID()]
		a.mu.Unlock()
		if !ok || b.conn == nil || hostname != b.host || c.RemoteAddr() != b.attempt.RemoteAddr || !time.Now().Before(b.expires) {
			return fmt.Errorf("host verification has no matching active attempt")
		}
		if caps["VerifyHostKey"] {
			r, err := child.VerifyHostKey(ctx, &libplugin.VerifyHostKeyRequest{Meta: metadata(c), Hostname: b.host, Netaddress: b.conn.RemoteAddr().String(), Key: key})
			if err != nil {
				return err
			}
			if !r.GetVerified() {
				return fmt.Errorf("upstream host key rejected by router")
			}
			return nil
		}
		if len(b.keys) == 0 {
			return nil
		}
		pub, err := ssh.ParsePublicKey(key)
		if err != nil {
			return err
		}
		return b.verify(b.host, b.conn.RemoteAddr(), pub)
	}
	if caps["UpstreamAuthFailure"] {
		cfg.UpstreamAuthFailureCallback = func(c libplugin.ConnMetadata, method string, failure error, allowed []string) {
			methods := make([]libplugin.AuthMethod, 0, len(allowed))
			for _, name := range allowed {
				methods = append(methods, libplugin.AuthMethodFromName(name))
			}
			_, _ = child.UpstreamAuthFailureNotice(ctx, &libplugin.UpstreamAuthFailureNoticeRequest{Meta: metadata(c), Method: method, Error: failure.Error(), AllowedMethods: methods})
		}
	}
	cfg.PipeStartCallback = func(c libplugin.ConnMetadata) {
		a.finish(c.UniqueID(), "", true)
		if caps["PipeStart"] {
			_, _ = child.PipeStartNotice(ctx, &libplugin.PipeStartNoticeRequest{Meta: metadata(c)})
		}
	}
	if caps["PipeError"] {
		cfg.PipeErrorCallback = func(c libplugin.ConnMetadata, err error) {
			_, _ = child.PipeErrorNotice(ctx, &libplugin.PipeErrorNoticeRequest{Meta: metadata(c), Error: err.Error()})
		}
	}
	cfg.PipeCreateErrorCallback = func(remote string, err error) {
		a.finish("", remote, false)
		if caps["PipeCreateError"] {
			_, _ = child.PipeCreateErrorNotice(ctx, &libplugin.PipeCreateErrorNoticeRequest{FromAddr: remote, Error: err.Error()})
		}
	}
	return cfg, nil
}

// metadata preserves the complete pinned generated message, including approval
// and audit fields. libplugin supplies this concrete type to every callback.
func metadata(c libplugin.ConnMetadata) *libplugin.ConnMeta {
	return c.(*libplugin.ConnMeta)
}

// bind leaves chain transitions intact and preserves host-key address identity
// while attaching a one-use capability for the selected TCP destination.
func (a *adapter) bind(c libplugin.ConnMetadata, u *libplugin.Upstream) (*libplugin.Upstream, error) {
	if u == nil {
		return nil, fmt.Errorf("router returned no upstream")
	}
	if u.GetNextPlugin() != nil || u.GetRetryCurrentPlugin() != nil {
		return u, nil
	}
	if u.GetRemoteSigner() != nil {
		return nil, fmt.Errorf("remote signing routes are not supported by this adapter")
	}
	if c.UniqueID() == "" || c.RemoteAddr() == "" {
		return nil, fmt.Errorf("routing connection identity is missing")
	}
	uri := u.GetOrGenerateUri()
	parsed, err := url.Parse(uri)
	if err != nil || parsed.Scheme != "tcp" || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.User != nil {
		return nil, fmt.Errorf("router must select a plain TCP endpoint")
	}
	if _, _, err := net.SplitHostPort(parsed.Host); err != nil {
		return nil, err
	}
	var verify ssh.HostKeyCallback
	if !a.childVerifier {
		verify, err = hostVerifier(u.GetKnownHostsData())
		if err != nil {
			return nil, err
		}
	}
	id := rand.Text()
	parsed.RawQuery = "containarium_attempt=" + id
	bound := parsed.String()
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.bindings) >= 4096 {
		for key, b := range a.bindings {
			if !time.Now().Before(b.expires) {
				delete(a.bindings, key)
			}
		}
		if len(a.bindings) >= 4096 {
			return nil, fmt.Errorf("routing attempt capacity exhausted")
		}
	}
	b := binding{attempt: Attempt{ID: id, ConnectionID: c.UniqueID(), RemoteAddr: c.RemoteAddr(), URI: uri}, expires: time.Now().Add(30 * time.Second), host: parsed.Host, keys: bytes.Clone(u.GetKnownHostsData()), verify: verify}
	for connection, old := range a.setups {
		if !time.Now().Before(old.expires) {
			delete(a.setups, connection)
		}
	}
	if _, active := a.setups[c.UniqueID()]; active || len(a.setups) >= 4096 {
		return nil, fmt.Errorf("routing setup capacity exhausted")
	}
	a.bindings[bound] = b
	a.setups[c.UniqueID()] = b
	// Clone so cached child replies and their credentials remain immutable.
	out := proto.Clone(u).(*libplugin.Upstream)
	out.Uri = bound
	return out, nil
}

// hostVerifier uses the existing knownhosts parser without maintaining a second
// parser or retaining files. The official dependency accepts filenames only.
func hostVerifier(data []byte) (ssh.HostKeyCallback, error) {
	if len(data) == 0 {
		return nil, nil
	}
	f, err := os.CreateTemp("", "containarium-upstream-known-hosts-*")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.Remove(f.Name()) }()
	_, writeErr := f.Write(data)
	closeErr := f.Close()
	if writeErr != nil {
		return nil, writeErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	return knownhosts.New(f.Name())
}

// connect consumes an exact bound URI before any socket is opened. Replays and
// URI substitutions cannot turn the adapter into an arbitrary TCP proxy.
func (a *adapter) connect(uri string) (net.Conn, error) {
	a.mu.Lock()
	b, ok := a.bindings[uri]
	delete(a.bindings, uri)
	a.mu.Unlock()
	if !ok || !time.Now().Before(b.expires) {
		return nil, fmt.Errorf("unknown or expired routing attempt")
	}
	conn, err := a.dial(a.ctx, b.attempt)
	if err != nil {
		return nil, err
	}
	if err := conn.SetDeadline(b.expires); err != nil {
		_ = conn.Close()
		return nil, err
	}
	a.mu.Lock()
	active, ok := a.setups[b.attempt.ConnectionID]
	if ok && active.attempt.ID == b.attempt.ID && time.Now().Before(active.expires) {
		active.conn = conn
		a.setups[b.attempt.ConnectionID] = active
	}
	a.mu.Unlock()
	if !ok || active.attempt.ID != b.attempt.ID || !time.Now().Before(active.expires) {
		_ = conn.Close()
		return nil, fmt.Errorf("routing attempt ended during dial")
	}
	return conn, nil
}

// finish releases only the pending setup; successful sessions keep their socket
// and lose the setup deadline. Failed or expired setups never become sessions.
func (a *adapter) finish(connection, remote string, ready bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for id, b := range a.setups {
		if id != connection && (remote == "" || b.attempt.RemoteAddr != remote) {
			continue
		}
		delete(a.setups, id)
		if b.conn != nil {
			if ready && time.Now().Before(b.expires) {
				_ = b.conn.SetDeadline(time.Time{})
			} else {
				_ = b.conn.Close()
			}
		}
	}
}
