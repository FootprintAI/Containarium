package engine

import (
	"fmt"
	"strings"
)

// Kind names a credential source. An enum-shaped string type, for the same
// reason Name is one: it is the value recorded in code.json and matched on in
// three places.
type Kind string

const (
	// KindSecret is the shipped behaviour: the box's own environment carries a
	// provider key, delivered by the daemon's secrets store
	// (/run/containarium/secrets.env) or placed there by the user.
	KindSecret Kind = "secret"
	// KindGateway is #1726's model gateway: the box holds a short-lived,
	// scoped, revocable gateway token instead of a provider key, and the real
	// upstream key never leaves the daemon.
	KindGateway Kind = "gateway"
)

// DefaultKind is what --credential resolves to when the flag is absent: the
// behaviour every box installed before #1727 already has.
const DefaultKind = KindSecret

// Preflight is the check `code install` must pass before it declares a box
// ready. It is an enum rather than a func on the interface because the checks
// need a daemon client, and this package deliberately has none — a pure,
// shell-rendering package is what makes the engine table unit-testable. The
// cmd layer switches on this value.
type Preflight int

const (
	// PreflightSecretMetadata reads the tenant secret's METADATA (name,
	// delivery mode) and asserts the delivery mode is one a shell session can
	// actually see. It never reads the value.
	PreflightSecretMetadata Preflight = iota
	// PreflightGatewayDryRun calls MintGatewayToken{dry_run:true}, which
	// validates box ownership, the provider, and that the resolved key owner
	// has a key — and issues nothing. It is how install names a
	// misconfiguration at install time rather than at the first model call.
	PreflightGatewayDryRun
)

func (p Preflight) String() string {
	switch p {
	case PreflightSecretMetadata:
		return "secret-metadata"
	case PreflightGatewayDryRun:
		return "gateway-dry-run"
	default:
		return fmt.Sprintf("Preflight(%d)", int(p))
	}
}

// CredentialSource is how one box's runs obtain a model credential.
type CredentialSource interface {
	// Kind is this source's identifier, as recorded in code.json.
	Kind() Kind
	// Preflight is the install-time check this source demands.
	Preflight() Preflight
}

// SecretCredential is the tenant-secret source.
//
// Name is the secret the engine's runs expect in their environment
// (ANTHROPIC_API_KEY, OPENAI_API_KEY, …). It is a NAME, never a value: nothing
// in this package or the install path reads a secret's plaintext, which is why
// the install-time check is metadata-only.
type SecretCredential struct {
	Name string
}

func (SecretCredential) Kind() Kind           { return KindSecret }
func (SecretCredential) Preflight() Preflight { return PreflightSecretMetadata }

// GatewayCredential is the model-gateway source. Provider is the gateway
// provider name (gatewayprovider.Name of the GatewayProvider enum) the token is
// minted for.
type GatewayCredential struct {
	Provider string
}

func (GatewayCredential) Kind() Kind           { return KindGateway }
func (GatewayCredential) Preflight() Preflight { return PreflightGatewayDryRun }

// Kinds lists every --credential value, for flag help and error messages.
func Kinds() []string { return []string{string(KindSecret), string(KindGateway)} }

// ParseCredentialKind resolves a --credential flag value. As with ParseName, an
// unknown value is an error naming the valid ones rather than a silent default:
// defaulting "gatewy" to a tenant secret would start billing the wrong party.
func ParseCredentialKind(s string) (Kind, error) {
	switch k := Kind(strings.ToLower(strings.TrimSpace(s))); k {
	case KindSecret, KindGateway:
		return k, nil
	default:
		return "", fmt.Errorf("unknown credential source %q (one of: %s)", s, strings.Join(Kinds(), ", "))
	}
}
