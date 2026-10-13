//go:build !windows && !containarium_client

package cmd

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/footprintai/containarium/internal/auth"
)

// sentinelTokenKind selects which credential `sentinel register-token` and
// `deregister-token` operate on (#2415). A typed pflag.Value rather than a
// string flag plus a comment listing the allowed values: an unknown kind is
// rejected at flag parse, before any request is built.
type sentinelTokenKind string

const (
	// sentinelTokenKindTunnelJoin is the original behavior (#799): a BYOC
	// tunnel-join token. It stays the default so existing invocations and
	// control-plane callers are byte-for-byte unchanged.
	sentinelTokenKindTunnelJoin sentinelTokenKind = "tunnel-join"
	// sentinelTokenKindAuditIngest registers a backend-scoped audit:ingest
	// JWT the sentinel's SSH session shipper uses to append to that
	// backend's audit chain.
	sentinelTokenKindAuditIngest sentinelTokenKind = "audit-ingest"
)

func (k *sentinelTokenKind) String() string { return string(*k) }

func (k *sentinelTokenKind) Set(v string) error {
	switch sentinelTokenKind(v) {
	case sentinelTokenKindTunnelJoin, sentinelTokenKindAuditIngest:
		*k = sentinelTokenKind(v)
		return nil
	}
	return fmt.Errorf("invalid kind %q (want %q or %q)", v, sentinelTokenKindTunnelJoin, sentinelTokenKindAuditIngest)
}

func (k *sentinelTokenKind) Type() string { return "kind" }

// sendSentinelAdminRequest signs body with the sentinel admin secret and
// sends it, treating anything but 204 as an error. Shared by register and
// deregister for both kinds.
func sendSentinelAdminRequest(method, endpoint, secret string, body []byte) error {
	req, err := http.NewRequest(method, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	auth.SignSentinelRequest(req, []byte(secret))

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("%s %s: %w", method, endpoint, err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("sentinel returned %d: %s", resp.StatusCode, string(respBody))
	}
	return nil
}
