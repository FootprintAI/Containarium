// Package sshauthz implements the sentinel side of SSH live authorization
// (docs/architecture/ssh-live-authorization.md, #2518): a sshpiperd plugin
// that calls the backend's SSHAuthzService on every public-key auth attempt,
// caches positive results, and stashes the decision in ConnMeta.Metadata so
// the ssh-session-plugin can record it.
//
// This is audit-only: the plugin never rejects. The enforce flag is a
// separate issue. APPROVAL_PENDING is treated as DENY here; the
// keyboard-interactive flow is umbrella B.
package sshauthz

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/footprintai/containarium/internal/sentinel"
	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/encoding/protojson"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// Decision mirrors SSHAuthzDecision. Using a typed constant rather than the
// proto enum directly keeps the plugin testable without proto generation and
// avoids a compile-time dependency on the generated package during the window
// between #2516 (proto contract) and the first `make proto` run.
type Decision int

const (
	DecisionUnspecified     Decision = 0
	DecisionAllow           Decision = 1
	DecisionDeny            Decision = 2
	DecisionApprovalPending Decision = 3
)

// String returns the proto enum name used in sshsession metadata.
func (d Decision) String() string {
	switch d {
	case DecisionAllow:
		return "SSH_AUTHZ_DECISION_ALLOW"
	case DecisionDeny:
		return "SSH_AUTHZ_DECISION_DENY"
	case DecisionApprovalPending:
		return "SSH_AUTHZ_DECISION_APPROVAL_PENDING"
	default:
		return "SSH_AUTHZ_DECISION_UNSPECIFIED"
	}
}

// DenyReason mirrors SSHDenyReason.
type DenyReason int

const (
	DenyReasonUnspecified         DenyReason = 0
	DenyReasonUnknownKey          DenyReason = 1
	DenyReasonUserDisabled        DenyReason = 2
	DenyReasonOrgPolicy           DenyReason = 3
	DenyReasonUpstreamUnavailable DenyReason = 4
	DenyReasonApprovalDenied      DenyReason = 5
	DenyReasonApprovalExpired     DenyReason = 6
)

// String returns the proto enum name used in sshsession metadata.
func (r DenyReason) String() string {
	switch r {
	case DenyReasonUnknownKey:
		return "SSH_DENY_REASON_UNKNOWN_KEY"
	case DenyReasonUserDisabled:
		return "SSH_DENY_REASON_USER_DISABLED"
	case DenyReasonOrgPolicy:
		return "SSH_DENY_REASON_ORG_POLICY"
	case DenyReasonUpstreamUnavailable:
		return "SSH_DENY_REASON_UPSTREAM_UNAVAILABLE"
	case DenyReasonApprovalDenied:
		return "SSH_DENY_REASON_APPROVAL_DENIED"
	case DenyReasonApprovalExpired:
		return "SSH_DENY_REASON_APPROVAL_EXPIRED"
	default:
		return "SSH_DENY_REASON_UNSPECIFIED"
	}
}

// Result is the outcome of a single Authorize call.
type Result struct {
	Decision   Decision
	DenyReason DenyReason
	// UserID is set when Decision == DecisionAllow.
	UserID string
	// CacheTTL is how long a positive result should be cached.
	// Zero means do not cache.
	CacheTTL time.Duration
}

// Authorizer is the interface the plugin uses to check a credential with the
// backend. The HTTP implementation below calls POST /v1/ssh/authorize;
// the fake implementation in tests returns whatever the test fixture says.
type Authorizer interface {
	// Authorize calls the backend and returns a decision for the given
	// (login, backendURL, fingerprint, clientAddr) tuple. A network or
	// 5xx error is returned as error; the caller decides whether to use
	// the positive cache or treat it as DENY UPSTREAM_UNAVAILABLE.
	Authorize(ctx context.Context, backendURL, login, fingerprint, clientAddr string) (Result, error)
}

// HTTPAuthorizer calls POST /v1/ssh/authorize on the backend's REST API,
// sentinel-signed (#688). The path is defined by the proto's http annotation
// (see proto/containarium/v1/ssh_authz.proto).
type HTTPAuthorizer struct {
	// Client is the HTTP transport; nil uses http.DefaultClient.
	Client *http.Client
	// Sign stamps the sentinel's request signature. nil sends unsigned
	// requests (tests wiring a stub daemon that skips auth).
	Sign func(*http.Request)
}

const authorizePath = "/v1/ssh/authorize"

// Authorize implements Authorizer.
func (a *HTTPAuthorizer) Authorize(ctx context.Context, backendURL, login, fingerprint, clientAddr string) (Result, error) {
	req := &pb.AuthorizeSSHRequest{
		Login:      login,
		Backend:    backendURL, // informational backend identifier
		ClientAddr: clientAddr,
		Credential: &pb.SSHCredential{
			Fingerprint: fingerprint,
		},
	}
	body, err := protojson.Marshal(req)
	if err != nil {
		return Result{}, fmt.Errorf("ssh-authz: encode request: %w", err)
	}

	url := strings.TrimRight(backendURL, "/") + authorizePath
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return Result{}, fmt.Errorf("ssh-authz: build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if a.Sign != nil {
		a.Sign(httpReq)
	}

	client := a.Client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(httpReq)
	if err != nil {
		return Result{}, fmt.Errorf("ssh-authz: backend unreachable: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	if resp.StatusCode >= 500 {
		// 5xx — treat as upstream unavailable; caller checks the grace cache.
		return Result{}, fmt.Errorf("ssh-authz: backend returned HTTP %d", resp.StatusCode)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var e struct {
			Error   string `json:"error"`
			Message string `json:"message"`
		}
		_ = json.Unmarshal(raw, &e)
		msg := e.Error
		if msg == "" {
			msg = e.Message
		}
		if msg == "" {
			msg = fmt.Sprintf("HTTP %d", resp.StatusCode)
		}
		return Result{}, fmt.Errorf("ssh-authz: backend: %s", msg)
	}

	out := &pb.AuthorizeSSHResponse{}
	if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(raw, out); err != nil {
		return Result{}, fmt.Errorf("ssh-authz: decode response: %w", err)
	}

	res := Result{
		Decision:   Decision(out.GetDecision()),
		DenyReason: DenyReason(out.GetDenyReason()),
		UserID:     out.GetUserId(),
	}
	if d := out.GetCacheTtl(); d != nil {
		res.CacheTTL = d.AsDuration()
	}
	return res, nil
}

// NewHTTPAuthorizer returns an Authorizer that calls the backend over HTTP,
// signing requests with the sentinel's own identity (sentinel.SignRequest).
func NewHTTPAuthorizer(client *http.Client) *HTTPAuthorizer {
	return &HTTPAuthorizer{
		Client: client,
		Sign:   sentinel.SignRequest,
	}
}

// keyType returns the SSHKeyType for a parsed public key, used to populate
// the proto SSHCredential.key_type field.
func keyType(pub ssh.PublicKey) pb.SSHKeyType {
	switch pub.Type() {
	case ssh.KeyAlgoED25519:
		return pb.SSHKeyType_SSH_KEY_TYPE_ED25519
	case ssh.KeyAlgoECDSA256:
		return pb.SSHKeyType_SSH_KEY_TYPE_ECDSA_P256
	case ssh.KeyAlgoECDSA384:
		return pb.SSHKeyType_SSH_KEY_TYPE_ECDSA_P384
	case ssh.KeyAlgoRSA:
		return pb.SSHKeyType_SSH_KEY_TYPE_RSA
	default:
		return pb.SSHKeyType_SSH_KEY_TYPE_UNSPECIFIED
	}
}
