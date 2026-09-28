package secrets

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"regexp"
	"strings"
	"time"
)

// Per-owner model-gateway provider keys.
//
// The daemon's model gateway can broker calls for several key owners, each
// spending their own upstream key (internal/modelgateway, `key_owner` claim).
// Those keys need the same custody as any tenant secret — encrypted at rest,
// KMS-enveloped in production — so they live in THIS store rather than in a
// second one, under a reserved namespace:
//
//	__gateway/<key_owner>/<provider>
//
// which maps onto the store's (username, name) pair as
// username="__gateway/<key_owner>", name="<PROVIDER>". The split is forced by
// the store's own name rule (env-var-shaped, `^[A-Z_][A-Z0-9_]*$`), which a
// single literal path could never satisfy.
//
// Two properties this namespace has to have, and how it gets them:
//
//   - No tenant can ever list, read, overwrite or delete one. A '/' cannot
//     appear in a tenant username, so the reserved namespace is disjoint from
//     every tenant's by construction rather than by a filter someone has to
//     remember. On top of that, the tenant-facing methods refuse the namespace
//     outright (ErrReservedNamespace), so an RPC that forwards a
//     caller-supplied username cannot reach it either.
//   - No delivery mode ever ships one into a box. The rows are stored with
//     DeliveryBroker, which LoadAllForUserWithDelivery — the single funnel every
//     delivery path goes through — already excludes.

// gatewayKeyNamespacePrefix prefixes the reserved username of every per-owner
// gateway key. The '/' is what makes it unreachable as a tenant username.
const gatewayKeyNamespacePrefix = "__gateway/"

// ErrReservedNamespace is returned by the tenant-facing store methods when the
// username names the reserved model-gateway namespace. Per-owner gateway keys
// are reachable only through the SetGatewayProviderKey / KeyFor /
// DeleteGatewayProviderKey trio below.
var ErrReservedNamespace = errors.New("secrets: reserved namespace")

// maxKeyOwnerLen caps a key owner id. Both shapes it takes (a local username,
// a UUID) are far shorter; the cap is here so a hostile caller cannot grow the
// username column without bound.
const maxKeyOwnerLen = 200

// gatewayProviderRE is the provider-name shape, mirroring the gateway's own
// rule (internal/modelgateway's providerNameRE — duplicated rather than
// imported so this package keeps no dependency on the gateway).
var gatewayProviderRE = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)

// IsGatewayKeyNamespace reports whether username names the reserved per-owner
// gateway-key namespace rather than a tenant.
func IsGatewayKeyNamespace(username string) bool {
	return strings.HasPrefix(username, gatewayKeyNamespacePrefix)
}

// GatewayKeyLocation maps a (key owner, provider) pair to the store coordinates
// its key lives at: the reserved username and the secret name. Exported so the
// daemon's gateway wiring and its tests can name the same location without
// rebuilding the string by hand.
func GatewayKeyLocation(keyOwner, provider string) (username, name string, err error) {
	if keyOwner == "" {
		return "", "", fmt.Errorf("secrets: gateway key: key owner is required")
	}
	if len(keyOwner) > maxKeyOwnerLen {
		return "", "", fmt.Errorf("secrets: gateway key: key owner is longer than %d characters", maxKeyOwnerLen)
	}
	// A '/' would let a key owner pick which provider's (or which other
	// owner's) row it lands on; whitespace and control characters have no
	// business in an identifier that ends up in log lines and audit rows.
	if strings.ContainsAny(keyOwner, "/") || strings.ContainsFunc(keyOwner, isSpaceOrControl) {
		return "", "", fmt.Errorf("secrets: gateway key: key owner %q may not contain '/', whitespace or control characters", keyOwner)
	}
	if !gatewayProviderRE.MatchString(provider) {
		return "", "", fmt.Errorf("secrets: gateway key: provider %q must match %s", provider, gatewayProviderRE)
	}
	return gatewayKeyNamespacePrefix + keyOwner, strings.ToUpper(strings.ReplaceAll(provider, "-", "_")), nil
}

// isSpaceOrControl reports whether r is whitespace or a control character.
func isSpaceOrControl(r rune) bool {
	return r <= ' ' || r == 0x7f
}

// SetGatewayProviderKey stores (or rotates) the REAL upstream key one key owner
// pays with for one provider. Stored with DeliveryBroker, so no delivery path
// can ship it to a box and Get refuses to read it back.
func (s *Store) SetGatewayProviderKey(ctx context.Context, keyOwner, provider, key string) error {
	username, name, err := GatewayKeyLocation(keyOwner, provider)
	if err != nil {
		return err
	}
	if key == "" {
		return fmt.Errorf("secrets: gateway key: key is required")
	}
	_, err = s.set(ctx, username, name, key, DeliveryBroker)
	return err
}

// gatewayKeyFingerprintHexLen is how much of the SHA-256 the fingerprint shows:
// 16 hex characters (64 bits). Enough that "the key I pushed is the key that is
// stored" is answerable and a collision is not something anyone will see;
// nowhere near enough to be worth attacking.
const gatewayKeyFingerprintHexLen = 16

// GatewayKeyFingerprint is the display-only identity of a provider key: the
// first gatewayKeyFingerprintHexLen hex characters of its SHA-256. It is the
// ONLY key-derived value the ModelGatewayService status RPC ever returns — the
// key itself has no read path on that API.
//
// An empty key has no fingerprint (rather than the SHA-256 of ""), so "unset"
// can never be mistaken for "set to something".
func GatewayKeyFingerprint(key string) string {
	if key == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])[:gatewayKeyFingerprintHexLen]
}

// GatewayKeyStatus is the metadata half of a per-owner gateway key: enough to
// confirm which key is registered and when, and nothing that could spend it.
type GatewayKeyStatus struct {
	// Set reports whether a key is registered for this (key owner, provider).
	Set bool
	// Fingerprint is GatewayKeyFingerprint of the stored key; empty when unset.
	Fingerprint string
	// SetAt is when the row was last written (a rotation moves it).
	SetAt time.Time
}

// GatewayProviderKeyStatus reports whether one owner has a key for one provider
// and, if so, its fingerprint and when it was last set.
//
// It reads the key in order to fingerprint it and then does not return it — the
// fingerprint has to be derived from what is actually stored, or it would be a
// claim about the caller's input rather than about the store's contents. A
// missing row is (Set:false) with a nil error: "no key here" is an answer, not
// a failure.
func (s *Store) GatewayProviderKeyStatus(ctx context.Context, keyOwner, provider string) (GatewayKeyStatus, error) {
	username, name, err := GatewayKeyLocation(keyOwner, provider)
	if err != nil {
		return GatewayKeyStatus{}, err
	}
	meta, value, err := s.getRaw(ctx, username, name)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return GatewayKeyStatus{}, nil
		}
		return GatewayKeyStatus{}, err
	}
	// Same refusal as KeyFor: a row that is not broker-only did not come from
	// SetGatewayProviderKey, so do not describe it as this owner's gateway key.
	if meta.Delivery != DeliveryBroker {
		log.Printf("secrets: gateway key %s/%s has delivery %q, want %q; reporting it as unset", username, name, meta.Delivery, DeliveryBroker)
		return GatewayKeyStatus{}, nil
	}
	return GatewayKeyStatus{
		Set:         true,
		Fingerprint: GatewayKeyFingerprint(value),
		SetAt:       meta.UpdatedAt,
	}, nil
}

// DeleteGatewayProviderKey removes one owner's key for one provider. Returns
// ErrNotFound when there was none, so a caller can report a clean 404 — the
// same contract as Delete.
func (s *Store) DeleteGatewayProviderKey(ctx context.Context, keyOwner, provider string) error {
	username, name, err := GatewayKeyLocation(keyOwner, provider)
	if err != nil {
		return err
	}
	return s.deleteSecret(ctx, username, name)
}

// KeyFor returns the REAL upstream key for (keyOwner, provider) and whether one
// exists, satisfying modelgateway.KeyResolver — which is how the gateway
// resolves a `key_owner` token's key without this package importing the gateway
// or the gateway importing Postgres.
//
// Deliberately (string, bool) and not (string, error): to the gateway, "this
// owner has no key here" is a normal outcome that falls back to the
// daemon-global key, not a failure. A lookup that genuinely failed (database
// down, undecryptable row) is logged here and then reported as "no key", so it
// takes the same fallback — noisy on both sides, but it does not fail a model
// call over a transient database error. Distinguishing the two would need a
// resolver that can return an error, which the gateway's interface does not
// carry today.
func (s *Store) KeyFor(ctx context.Context, keyOwner, provider string) (string, bool) {
	username, name, err := GatewayKeyLocation(keyOwner, provider)
	if err != nil {
		return "", false
	}
	meta, value, err := s.getRaw(ctx, username, name)
	if err != nil {
		if !errors.Is(err, ErrNotFound) {
			log.Printf("secrets: gateway key lookup failed for %s/%s: %v", username, name, err)
		}
		return "", false
	}
	// A row that is not broker-only did not come from SetGatewayProviderKey.
	// Refuse it rather than spend a key whose custody rules are unknown.
	if meta.Delivery != DeliveryBroker {
		log.Printf("secrets: gateway key %s/%s has delivery %q, want %q; refusing to use it", username, name, meta.Delivery, DeliveryBroker)
		return "", false
	}
	return value, true
}
