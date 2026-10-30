package notify

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"syscall"
	"time"
)

// Channel is a user's ntfy destination. The token is never part of it: the
// daemon keeps it as a broker-only tenant secret named by TokenSecret and
// passes it to Send separately.
type Channel struct {
	Username string
	Server   string
	Topic    string
	// TokenSecret names the broker-only secret holding the channel's token;
	// empty for a channel without one. Each token gets a fresh name
	// (NewTokenSecretName) that is never rewritten, so a channel row and the
	// secret it names always belong together: replacing a token is a single
	// write of the row that points at the new secret.
	TokenSecret string
	// RedactCommand sends the tool name only, never its command.
	RedactCommand bool
	UpdatedAt     time.Time
}

// HasToken says a token is stored for the channel.
func (c Channel) HasToken() bool { return c.TokenSecret != "" }

// TokenSecretPrefix starts the name of every secret holding a channel token.
const TokenSecretPrefix = "CONTAINARIUM_NOTIFY_NTFY_TOKEN_"

// NewTokenSecretName returns a fresh secret name for a channel token.
func NewTokenSecretName() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("notify: token secret name: %w", err)
	}
	return TokenSecretPrefix + strings.ToUpper(hex.EncodeToString(b[:])), nil
}

// topicPattern is ntfy's own topic rule.
var topicPattern = regexp.MustCompile(`^[-_A-Za-z0-9]{1,64}$`)

// ValidateChannel checks a channel before it is stored. The server must be a
// bare http(s) URL (a path prefix is allowed, for ntfy behind a reverse
// proxy); with a token it must be https, so the token never crosses the
// network in clear.
func ValidateChannel(ch Channel, hasToken bool) error {
	u, err := url.Parse(strings.TrimSpace(ch.Server))
	if err != nil || ch.Server == "" {
		return fmt.Errorf("server must be an http(s) URL, got %q", ch.Server)
	}
	switch {
	case u.Scheme != "http" && u.Scheme != "https":
		return fmt.Errorf("server must be an http(s) URL, got %q", ch.Server)
	case u.Host == "":
		return fmt.Errorf("server %q has no host", ch.Server)
	case u.User != nil:
		return errors.New("server must not carry credentials; pass the token with --token-file or --token-stdin")
	case u.RawQuery != "" || u.Fragment != "" || u.Opaque != "":
		return fmt.Errorf("server %q must not have a query or fragment", ch.Server)
	case hasToken && u.Scheme != "https":
		return errors.New("a channel with a token needs an https server, so the token is never sent in clear")
	}
	if !topicPattern.MatchString(ch.Topic) {
		return fmt.Errorf("topic must be 1-64 letters, digits, '-' or '_', got %q", ch.Topic)
	}
	return nil
}

// Sender delivers messages to ntfy.
type Sender struct {
	client *http.Client
}

// sendTimeout bounds one push, connect included.
const sendTimeout = 10 * time.Second

// NewSender returns the daemon's sender. The server is chosen by a tenant, so
// it never follows a redirect (that would carry the token to another host)
// and refuses, at connect time, loopback, link-local (cloud metadata
// included) and unspecified addresses, and private, CGNAT, benchmarking and
// ULA addresses
// (the daemon's own LAN and the box bridge) unless allowed lists the
// network: a self-hosted ntfy is reached only where the operator said so.
func NewSender(allowed []netip.Prefix) *Sender {
	d := &net.Dialer{
		Timeout: sendTimeout,
		Control: func(_, address string, _ syscall.RawConn) error { return checkDialAddr(address, allowed) },
	}
	return newSender(&http.Transport{
		Proxy:               nil,
		DialContext:         d.DialContext,
		TLSHandshakeTimeout: sendTimeout,
		MaxIdleConns:        8,
		IdleConnTimeout:     90 * time.Second,
	})
}

// AllowedCIDRsEnv names the daemon setting that lists the private networks a
// self-hosted ntfy server may be on, comma-separated (#2185).
const AllowedCIDRsEnv = "CONTAINARIUM_NOTIFY_ALLOWED_CIDRS"

// ParseAllowedCIDRs parses an AllowedCIDRsEnv value. Empty entries are
// ignored; any malformed entry is an error.
func ParseAllowedCIDRs(v string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, f := range strings.Split(v, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		p, err := netip.ParsePrefix(f)
		if err != nil {
			return nil, fmt.Errorf("%s: %q is not a CIDR", AllowedCIDRsEnv, f)
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

func newSender(rt http.RoundTripper) *Sender {
	return &Sender{client: &http.Client{
		Transport: rt,
		Timeout:   sendTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}}
}

// metadataAddrs are cloud metadata endpoints outside the link-local ranges
// (169.254.169.254, used by most clouds, is link-local and refused as such).
// Only the exact addresses: 100.64.0.0/10 as a whole stays allowed, since a
// self-hosted ntfy can sit on a CGNAT-range overlay network.
var metadataAddrs = []netip.Addr{
	netip.MustParseAddr("fd00:ec2::254"),   // AWS IMDS over IPv6
	netip.MustParseAddr("fd20:ce::254"),    // GCP metadata over IPv6
	netip.MustParseAddr("100.100.100.200"), // Alibaba Cloud metadata
}

// internalRanges are non-public IPv4 ranges netip.Addr.IsPrivate does not
// cover: CGNAT (RFC 6598) and the benchmarking range (RFC 2544), either of
// which can be routed to internal hosts.
var internalRanges = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("198.18.0.0/15"),
}

func isInternal(ip netip.Addr) bool {
	if ip.IsPrivate() {
		return true
	}
	for _, p := range internalRanges {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// checkDialAddr refuses the addresses a tenant-chosen server must not reach
// from the daemon's network position. Loopback, link-local and metadata
// addresses are refused whatever allowed says; a private, CGNAT or ULA
// address (see isInternal) is accepted only inside an allowed network.
func checkDialAddr(address string, allowed []netip.Prefix) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return fmt.Errorf("notify: refusing non-IP dial address %q", address)
	}
	ip = ip.Unmap()
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() {
		return fmt.Errorf("notify: refusing to connect to %s", ip)
	}
	for _, m := range metadataAddrs {
		if ip == m {
			return fmt.Errorf("notify: refusing to connect to %s", ip)
		}
	}
	if isInternal(ip) {
		for _, p := range allowed {
			if p.Contains(ip) {
				return nil
			}
		}
		return fmt.Errorf("notify: refusing to connect to private address %s (not in %s)", ip, AllowedCIDRsEnv)
	}
	return nil
}

// publishBody is ntfy's JSON publish form. JSON, not the Title header, so a
// title outside ASCII arrives intact.
type publishBody struct {
	Topic    string   `json:"topic"`
	Title    string   `json:"title,omitempty"`
	Message  string   `json:"message"`
	Tags     []string `json:"tags,omitempty"`
	Priority int      `json:"priority"`
}

// ntfyPriorityHigh is ntfy's priority 4 ("high"): a waiting run is worth a
// buzz, not an urgent alarm.
const ntfyPriorityHigh = 4

// Send publishes m to ch's topic. token may be empty for a topic that needs
// none. Errors never include the token.
func (s *Sender) Send(ctx context.Context, ch Channel, token string, m Message) error {
	body, err := json.Marshal(publishBody{Topic: ch.Topic, Title: m.Title, Message: m.Body, Tags: m.Tags, Priority: ntfyPriorityHigh})
	if err != nil {
		return fmt.Errorf("ntfy request: %w", err)
	}
	// JSON publishes go to the server root; a path prefix is kept for ntfy
	// behind a reverse proxy.
	endpoint := strings.TrimRight(strings.TrimSpace(ch.Server), "/") + "/"
	ctx, cancel := context.WithTimeout(ctx, sendTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("ntfy request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return fmt.Errorf("ntfy publish to %s: %w", ch.Server, err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("ntfy publish to %s: HTTP %d", ch.Server, resp.StatusCode)
	}
	return nil
}
