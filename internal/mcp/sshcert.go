package mcp

// Short-lived SSH certificates for the `connect` tool.
//
// `connect` authorizes a managed long-lived key on the box
// (POST /v1/containers/<box>/ssh-keys) and dials with it. That works, but it
// leaves a durable credential on every box the agent has ever touched, and
// those copies drift — after a host restart a box can be left with stale
// authorized_keys and no working login.
//
// When the server is a control plane that can sign certificates, there is a
// better answer: generate a throwaway keypair, have it signed for exactly this
// box, and use a certificate that expires in minutes. Nothing is installed on
// the box, so nothing is left behind and nothing can go stale.
//
// CAPABILITY-DETECTED, NOT CONFIGURED. A plain Containarium daemon has no
// signing endpoint, and asking a user to set a flag to describe which kind of
// server they pointed at is a flag they will get wrong. So `connect` tries to
// issue, and falls back to the managed key when the endpoint is absent. The
// fallback is the common path today and is what the tests exercise hardest.

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// certIssuePath is the control-plane endpoint that signs a public key.
const certIssuePath = "/v1/ssh/certificates:issue"

// errCertUnsupported means the server does not sign certificates — a plain
// daemon rather than a control plane. Callers fall back to the managed key.
//
// Distinct from every other failure on purpose: "this server cannot do
// certificates" is a routine deployment fact, while "the server could and
// refused" is a real problem the operator should see rather than have silently
// papered over by a fallback.
var errCertUnsupported = errors.New("this server does not issue SSH certificates")

// issuedCert is a signed certificate plus the ephemeral key it belongs to.
type issuedCert struct {
	// PrivateKeyPath is a throwaway key in a 0700 dir. Cleanup removes it.
	PrivateKeyPath string
	Principals     []string
	ValidBefore    time.Time
	// Cleanup removes the key material. Always non-nil when err == nil, and
	// callers must defer it — a certificate login that leaves its key behind
	// has given up the property it exists for.
	Cleanup func()
}

// issueCertForBox asks the server for a certificate scoped to one box.
//
// box is the SSH login name (`cld-<short>`), which is what an MCP client has:
// the OSS container projection carries no cloud UUID. The control plane
// accepts either.
func issueCertForBox(client API, box string) (*issuedCert, error) {
	// Reuse the package's existing generator rather than a second copy of
	// the same 10 lines.
	pubAuthorized, privPEM, err := generateEphemeralSSHKey("containarium mcp connect")
	if err != nil {
		return nil, err
	}

	raw, err := client.doRequest("POST", certIssuePath, map[string]any{
		"public_key": pubAuthorized,
		// Scoped to this box alone. Sending an empty list would ask for every
		// container the token can reach, which on an org-wide token is a
		// certificate for the whole org — the opposite of what a per-box
		// connect should hold.
		"container_ids": []string{box},
	})
	if err != nil {
		if isCertUnsupported(err) {
			return nil, errCertUnsupported
		}
		return nil, fmt.Errorf("issue certificate for %q: %w", box, err)
	}

	var resp struct {
		Certificate string   `json:"certificate"`
		Principals  []string `json:"principals"`
		ValidBefore string   `json:"validBefore"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, fmt.Errorf("decode certificate response: %w", err)
	}
	if strings.TrimSpace(resp.Certificate) == "" {
		// A 200 with no certificate is not something to fall back from
		// quietly: the server claimed to sign and produced nothing.
		return nil, errors.New("the server returned an empty certificate")
	}

	dir, err := os.MkdirTemp("", "containarium-cert-")
	if err != nil {
		return nil, fmt.Errorf("create identity dir: %w", err)
	}
	cleanup := func() { _ = os.RemoveAll(dir) }

	keyPath := filepath.Join(dir, "id_ed25519")
	// 0600 — ssh refuses a looser private key, and is right to.
	if err := os.WriteFile(keyPath, privPEM, 0o600); err != nil {
		cleanup()
		return nil, fmt.Errorf("write ephemeral key: %w", err)
	}
	cert := resp.Certificate
	if !strings.HasSuffix(cert, "\n") {
		cert += "\n"
	}
	// OpenSSH only presents a certificate that sits next to its private key
	// as "<key>-cert.pub"; anywhere else and it is silently ignored.
	if err := os.WriteFile(keyPath+"-cert.pub", []byte(cert), 0o600); err != nil {
		cleanup()
		return nil, fmt.Errorf("write certificate: %w", err)
	}

	out := &issuedCert{
		PrivateKeyPath: keyPath,
		Principals:     resp.Principals,
		Cleanup:        cleanup,
	}
	if resp.ValidBefore != "" {
		if t, perr := time.Parse(time.RFC3339, resp.ValidBefore); perr == nil {
			out.ValidBefore = t
		}
	}
	return out, nil
}

// isCertUnsupported reports whether an error means the endpoint is not there,
// as opposed to being there and refusing.
//
// Matching on the message is unlovely, but doRequest flattens the status code
// into an error string, and widening that seam for this one caller would touch
// every backend implementation. The trade is contained by failing toward
// "supported": anything unrecognised is surfaced to the operator rather than
// silently downgraded to the long-lived-key path, so a real failure cannot
// hide behind the fallback.
func isCertUnsupported(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	for _, marker := range []string{
		"404",
		"not found",
		"501",
		"not implemented",
		"unimplemented",
		"unknown method",
	} {
		if strings.Contains(msg, marker) {
			return true
		}
	}
	return false
}

// certTTLNote renders the remaining lifetime for the human-facing config-mode
// output, so it is obvious the invocation is perishable.
func certTTLNote(c *issuedCert, now time.Time) string {
	if c.ValidBefore.IsZero() {
		return "a short-lived certificate"
	}
	return fmt.Sprintf("a certificate valid for %s", c.ValidBefore.Sub(now).Round(time.Second))
}
