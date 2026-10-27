package notify

import (
	"bytes"
	"context"
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
// daemon keeps it as a broker-only secret (TokenSecretName) and passes it to
// Send separately.
type Channel struct {
	Username string
	Server   string
	Topic    string
	// HasToken says a token is stored for the channel.
	HasToken bool
	// RedactCommand sends the tool name only, never its command.
	RedactCommand bool
	UpdatedAt     time.Time
}

// TokenSecretName is the tenant secret that holds a channel's ntfy access
// token, in broker-only delivery: never stamped into any box.
const TokenSecretName = "CONTAINARIUM_NOTIFY_NTFY_TOKEN"

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
// included) and unspecified addresses. Private LAN addresses stay allowed,
// for a self-hosted ntfy.
func NewSender() *Sender {
	d := &net.Dialer{
		Timeout: sendTimeout,
		Control: func(_, address string, _ syscall.RawConn) error { return checkDialAddr(address) },
	}
	return newSender(&http.Transport{
		Proxy:               nil,
		DialContext:         d.DialContext,
		TLSHandshakeTimeout: sendTimeout,
		MaxIdleConns:        8,
		IdleConnTimeout:     90 * time.Second,
	})
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

// metadataAddrs are cloud metadata endpoints outside the link-local ranges.
var metadataAddrs = []netip.Addr{
	netip.MustParseAddr("fd00:ec2::254"), // AWS IMDS over IPv6
}

// checkDialAddr refuses the addresses a tenant-chosen server must not reach
// from the daemon's network position.
func checkDialAddr(address string) error {
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
