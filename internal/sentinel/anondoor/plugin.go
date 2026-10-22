// Package anondoor is the sshpiperd plugin behind `ssh new.<cloud-domain>`
// (docs/architecture/ssh-new-anonymous-box.md, #2198): the sentinel-side
// half of the anonymous-box door.
//
// It runs in a SECOND sshpiperd instance bound to the door's address,
// chained after the sshsession audit plugin. On public-key auth it asks
// the anon-pool daemon's AnonymousBoxService for "the box for this key"
// (POST /v1/anon/boxes:ensure, signed with the sentinel's own request
// signature — no new secret) and hands sshpiper an upstream pipe to it,
// authenticated with the same /etc/sshpiper/upstream_key every tenant
// pipe uses. sshpiper does the proxying, host keys, fail2ban and, via
// sshsession, the audit record. Any non-OK answer is a rejected auth, so
// the door never pipes to a half-provisioned box.
//
// Only public keys are accepted: the key IS the identity. Password and
// keyboard-interactive are refused, and the banner says so, since the
// rejection reason of a failed public-key auth is not something the SSH
// protocol delivers to the client (it sees "Permission denied"); the
// reason is logged on the sentinel and carried in the sshsession record.
package anondoor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/tg123/sshpiper/libplugin"
	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/encoding/protojson"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

const (
	// EnsurePath is grpc-gateway's mapping of AnonymousBoxService.EnsureAnonymousBox.
	EnsurePath = "/v1/anon/boxes:ensure"
	// DefaultUpstreamKeyPath is the key sshpiper authenticates to every box with.
	DefaultUpstreamKeyPath = "/etc/sshpiper/upstream_key"
	// DefaultTimeout bounds one Ensure call: a cold VM boot sits inside it,
	// and it must stay under sshpiperd's login grace so a slow daemon is a
	// clean rejection rather than a hung client.
	DefaultTimeout = 90 * time.Second
	// DefaultBanner is shown before authentication.
	DefaultBanner = "Containarium anonymous box: connect with an SSH key (no password).\n" +
		"If you are refused, the door may be closed or full - try again in a minute.\n"
)

// Config is everything the plugin needs.
type Config struct {
	// DaemonURL is the anon-pool daemon's REST base, e.g. http://<ip>:8080.
	DaemonURL string
	// UpstreamKeyPath is the private key the pipe authenticates with.
	UpstreamKeyPath string
	// Sign stamps the sentinel's request signature; nil sends unsigned
	// (tests), which a real daemon rejects.
	Sign func(*http.Request)
	// Timeout bounds one Ensure call. 0 = DefaultTimeout.
	Timeout time.Duration
	// Banner is sent to the client before auth. "" = DefaultBanner.
	Banner string
	// HTTPClient overrides the transport; nil = http.DefaultTransport.
	HTTPClient *http.Client
	// Logf receives one line per decision; nil = silent.
	Logf func(format string, args ...any)
}

// Plugin builds the sshpiperd callbacks.
type Plugin struct {
	cfg    Config
	ensure string // DaemonURL + EnsurePath
	client *http.Client
}

var errUseKey = errors.New("anonymous box: use an SSH key (password and keyboard-interactive are not accepted)")

// New validates cfg and applies defaults.
func New(cfg Config) (*Plugin, error) {
	u, err := url.Parse(cfg.DaemonURL)
	if err != nil || cfg.DaemonURL == "" || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, fmt.Errorf("anondoor: daemon url %q must be http(s)://host[:port]", cfg.DaemonURL)
	}
	if cfg.UpstreamKeyPath == "" {
		cfg.UpstreamKeyPath = DefaultUpstreamKeyPath
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultTimeout
	}
	if cfg.Banner == "" {
		cfg.Banner = DefaultBanner
	}
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{}
	}
	return &Plugin{
		cfg:    cfg,
		ensure: strings.TrimRight(cfg.DaemonURL, "/") + EnsurePath,
		client: client,
	}, nil
}

// PluginConfig returns the callbacks sshpiperd drives.
func (p *Plugin) PluginConfig() libplugin.SshPiperPluginConfig {
	return libplugin.SshPiperPluginConfig{
		NextAuthMethodsCallback: func(libplugin.ConnMetadata) ([]string, error) { return []string{"publickey"}, nil },
		NoClientAuthCallback: func(libplugin.ConnMetadata) (*libplugin.Upstream, error) {
			return nil, errUseKey
		},
		PasswordCallback: func(libplugin.ConnMetadata, []byte) (*libplugin.Upstream, error) {
			return nil, errUseKey
		},
		KeyboardInteractiveCallback: func(libplugin.ConnMetadata, libplugin.KeyboardInteractiveChallenge) (*libplugin.Upstream, error) {
			return nil, errUseKey
		},
		PublicKeyCallback: p.publicKeyCallback,
		BannerCallback:    func(libplugin.ConnMetadata) string { return p.cfg.Banner },
	}
}

// publicKeyCallback: key → fingerprint → daemon → upstream pipe.
func (p *Plugin) publicKeyCallback(conn libplugin.ConnMetadata, key []byte) (*libplugin.Upstream, error) {
	pub, err := ssh.ParsePublicKey(key)
	if err != nil {
		return nil, fmt.Errorf("anonymous box: invalid public key: %w", err)
	}
	fp := ssh.FingerprintSHA256(pub)
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))
	ip := sourceIP(conn.RemoteAddr())

	ctx, cancel := context.WithTimeout(context.Background(), p.cfg.Timeout)
	defer cancel()
	res, err := p.ensureBox(ctx, &pb.EnsureAnonymousBoxRequest{Fingerprint: fp, PublicKey: line, SourceIp: ip})
	if err != nil {
		p.cfg.Logf("[anondoor] %s from %s: rejected: %v", fp, ip, err)
		return nil, err
	}
	if res.GetSshHost() == "" || res.GetSshPort() == 0 || res.GetSshUser() == "" {
		p.cfg.Logf("[anondoor] %s from %s: daemon returned no ssh endpoint for %s", fp, ip, res.GetBoxName())
		return nil, errors.New("anonymous box: daemon returned no ssh endpoint")
	}
	upstreamKey, err := os.ReadFile(p.cfg.UpstreamKeyPath)
	if err != nil {
		p.cfg.Logf("[anondoor] %s from %s: box %s ready but upstream key unreadable: %v", fp, ip, res.GetBoxName(), err)
		return nil, fmt.Errorf("anonymous box: upstream key: %w", err)
	}
	p.cfg.Logf("[anondoor] %s from %s: box %s at %s:%d user %s (reused=%v previous_expired=%v)",
		fp, ip, res.GetBoxName(), res.GetSshHost(), res.GetSshPort(), res.GetSshUser(), res.GetReused(), res.GetPreviousExpired())
	return &libplugin.Upstream{
		Uri:      fmt.Sprintf("tcp://%s", net.JoinHostPort(res.GetSshHost(), strconv.Itoa(int(res.GetSshPort())))),
		UserName: res.GetSshUser(),
		// Same as every yaml pipe renderSSHPiperConfig emits: the box's host
		// key is minted at create and never reaches the sentinel, so there is
		// no known_hosts to pin. The tunnel/VPC is the trust boundary here.
		IgnoreHostKey: true, //nolint:staticcheck // deprecated upstream, still the mechanism tenant pipes use
		Auth: &libplugin.Upstream_PrivateKey{
			PrivateKey: &libplugin.UpstreamPrivateKeyAuth{PrivateKey: upstreamKey},
		},
	}, nil
}

// ensureBox is one POST /v1/anon/boxes:ensure. Transport failures and
// timeouts become "try again"; a non-2xx carries the daemon's own message
// (the gateway's {"error"} shape or grpc-gateway's {"message"} shape).
func (p *Plugin) ensureBox(ctx context.Context, req *pb.EnsureAnonymousBoxRequest) (*pb.EnsureAnonymousBoxResponse, error) {
	body, err := protojson.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("anonymous box: encode request: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, p.ensure, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("anonymous box: build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if p.cfg.Sign != nil {
		p.cfg.Sign(httpReq)
	}
	resp, err := p.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("anonymous box daemon unavailable, try again in a minute: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var e struct {
			Error   string `json:"error"`
			Message string `json:"message"`
		}
		_ = json.Unmarshal(raw, &e)
		switch {
		case e.Error != "":
			return nil, fmt.Errorf("anonymous box: %s", e.Error)
		case e.Message != "":
			return nil, fmt.Errorf("anonymous box: %s", e.Message)
		default:
			return nil, fmt.Errorf("anonymous box: daemon rejected the request (HTTP %d)", resp.StatusCode)
		}
	}
	out := &pb.EnsureAnonymousBoxResponse{}
	if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(raw, out); err != nil {
		return nil, fmt.Errorf("anonymous box: decode daemon response: %w", err)
	}
	return out, nil
}

// sourceIP strips the port from an sshpiper remote address; a bare value
// passes through so an unexpected format still reaches the daemon's label.
func sourceIP(remote string) string {
	if host, _, err := net.SplitHostPort(remote); err == nil {
		return host
	}
	return remote
}
