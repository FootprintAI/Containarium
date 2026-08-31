// Package secrets implements the daemon-side Postgres-backed store
// for tenant secrets, layered on top of pkg/core/secrets crypto.
// See docs/SECRETS-MANAGEMENT-DESIGN.md.
package secrets

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	corecrypto "github.com/footprintai/containarium/pkg/core/secrets"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// SecretMetadata is the public-safe view of a stored secret —
// matches the proto message of the same name. The plaintext value
// lives only in memory during Get and never in this struct.
type SecretMetadata struct {
	Username  string
	Name      string
	Version   int32
	CreatedAt time.Time
	UpdatedAt time.Time

	// Phase 4.3 — delivery mode. "env" (default) or "file".
	// Phase A lands the field; Phase B switches the stamping
	// path to honor it. See docs/security/SECRETS-ENV-VAR-RISK.md.
	Delivery string
}

// Delivery-mode constants. The DB column stores these
// strings literally; new values land here before the
// schema is taught to validate them.
const (
	DeliveryEnv  = "env"
	DeliveryFile = "file"
	// DeliveryCompose writes the secret into a shared dotenv file
	// (/run/containarium/secrets.env) that nested docker /
	// docker-compose apps consume via `env_file:` — they don't
	// inherit the LXC's Incus-config environment (the same gap OTel
	// solved, #370/#492). Values must be single-line; see Set.
	DeliveryCompose = "compose"
)

// ValidateDelivery returns nil for "" (defaults to env at the storage
// layer), "env", "file", or "compose". Anything else is caller-error
// and rejected at the API boundary.
func ValidateDelivery(mode string) error {
	switch mode {
	case "", DeliveryEnv, DeliveryFile, DeliveryCompose:
		return nil
	}
	return fmt.Errorf("secrets: delivery must be %q, %q, or %q; got %q",
		DeliveryEnv, DeliveryFile, DeliveryCompose, mode)
}

// ValidateValueForDelivery rejects a value that the chosen delivery mode
// can't represent. compose renders into a dotenv file (KEY=value lines),
// so a value with a newline would corrupt the file / be mangled by the
// `env_file:` parser — reject it at set-time and point at "file" delivery
// (per-secret tmpfs) for multi-line blobs. Pure function for testing.
func ValidateValueForDelivery(delivery, value string) error {
	if delivery == DeliveryCompose && strings.ContainsAny(value, "\r\n") {
		return fmt.Errorf("secrets: delivery %q requires a single-line value (no newlines); use %q delivery for multi-line secrets",
			DeliveryCompose, DeliveryFile)
	}
	return nil
}

// Store handles per-tenant secret persistence.
//
// Two encryption modes coexist on the same table (Phase 4.1 — see
// docs/security/KMS-ENVELOPE-DESIGN.md):
//
//   - Legacy: the row's nonce + ciphertext are AES-256-GCM under
//     the daemon's master key directly. wrapped_dek IS NULL,
//     kek_id IS NULL.
//   - Envelope: the row's nonce + ciphertext are AES-256-GCM
//     under a per-row Data Encryption Key (DEK). The DEK itself
//     is encrypted under the KMS-resident Key Encryption Key
//     (KEK) and stored in wrapped_dek; the KEK identifier is in
//     kek_id.
//
// Whether a Set produces a legacy or envelope row depends on
// whether the Store was constructed with a KMSClient. Sets
// without KMS write legacy rows; Sets with KMS write envelope
// rows. Get/LoadAllForUser dispatches per-row based on whether
// wrapped_dek IS NULL — so a deployment can run with mixed
// state (legacy rows from before the KMS rollout + new envelope
// rows) until Phase D's migration tool converts everything.
type Store struct {
	pool   *pgxpool.Pool
	cipher *corecrypto.Cipher
	kms    corecrypto.KMSClient // optional; nil = legacy-only mode

	// Phase 4.1 Phase-E — when true, the Store refuses
	// to decrypt any row whose wrapped_dek IS NULL.
	// Combined with KMS configured, this is the post-
	// retirement contract: every secret MUST be in
	// envelope form. Operators flip this after the
	// migrator reports 100% coverage; from that point
	// on, a legacy row hitting Get is a strong "you
	// missed a migration" signal that should page.
	requireEnvelope bool

	// #1630 — per-tenant KEK override. tenantKMSFactory is nil unless
	// the daemon's KMS backend is "gcp" (LoadTenantKMSFactory); a nil
	// factory means SetTenantKMSKey refuses rather than silently
	// no-op-ing.
	//
	// tenantKEK maps username -> the GCP key resource name that
	// username's NEW writes should wrap under (in-memory cache of the
	// tenant_kms_keys table, loaded once at construction and kept in
	// sync by SetTenantKMSKey/ClearTenantKMSKey).
	//
	// kekClients caches built KMSClient instances by key resource
	// name — shared between the encrypt path (resolveEncryptKMS,
	// keyed by tenantKEK) and the decrypt path (resolveDecryptKMS,
	// keyed by parsing the ROW's own kek_id). Decrypt being resolved
	// per-row rather than per-"current override" is what makes a
	// partially-completed SetTenantKMSKey/ClearTenantKMSKey safe: a
	// row still carrying its old kek_id keeps decrypting correctly
	// even while other rows for the same tenant have already moved to
	// the new key.
	tenantKMSFactory TenantKMSFactory
	tenantKEKMu      sync.RWMutex
	tenantKEK        map[string]string
	kekClientsMu     sync.RWMutex
	kekClients       map[string]corecrypto.KMSClient
}

// ErrNotFound is returned by Get / Delete when the (username, name)
// tuple has no row.
var ErrNotFound = errors.New("secrets: not found")

// ErrTenantKMSNotSupported is returned by SetTenantKMSKey when the
// daemon has no tenantKMSFactory configured (#1630) — i.e.
// CONTAINARIUM_KMS_BACKEND isn't "gcp". Callers map this to a
// caller-facing precondition failure, not an internal-error catch-all.
var ErrTenantKMSNotSupported = errors.New("secrets: per-tenant KMS keys require CONTAINARIUM_KMS_BACKEND=gcp")

// Option configures a Store at construction time. Phase 4.1 uses
// this to bolt on the KMS client without breaking the existing
// NewStore(ctx, pool, cipher) call sites.
type Option func(*Store)

// WithKMS enables envelope encryption. When set, every new Set
// produces an envelope row (wrapped_dek + kek_id populated).
// Reads accept both legacy and envelope rows.
//
// Passing nil is a no-op — equivalent to omitting WithKMS.
func WithKMS(kms corecrypto.KMSClient) Option {
	return func(s *Store) {
		if kms != nil {
			s.kms = kms
		}
	}
}

// WithRequireEnvelope enforces Phase-E retirement: every
// read MUST go through the envelope path. Legacy rows
// (wrapped_dek IS NULL) are rejected at Get / LoadAllForUser.
// Operators flip this on once `containarium secrets
// envelope-coverage` reports legacy=0 — at that point the
// master key is unused for production decrypts and the
// keyfile can be retired.
//
// Pairs with the daemon-side startup gate that refuses to
// start when require_envelope=true but no KMS backend is
// configured.
func WithRequireEnvelope(require bool) Option {
	return func(s *Store) {
		s.requireEnvelope = require
	}
}

// WithTenantKMSFactory enables per-tenant KEKs (#1630). Pass the result
// of secrets.LoadTenantKMSFactory() — nil is a no-op, equivalent to
// omitting this option, matching WithKMS's convention.
func WithTenantKMSFactory(f TenantKMSFactory) Option {
	return func(s *Store) {
		if f != nil {
			s.tenantKMSFactory = f
		}
	}
}

// NewStore opens the secrets store. Creates the `secrets` table on
// first run and applies any column migrations; idempotent on every
// subsequent call.
//
// The cipher must already be constructed from the daemon's master
// key (see pkg/core/secrets.LoadOrCreateMasterKey + NewCipher) —
// it's the LEGACY-path crypto and stays required even when
// WithKMS is supplied, because existing legacy rows still need it
// for decrypt until Phase D's migration runs.
func NewStore(ctx context.Context, pool *pgxpool.Pool, cipher *corecrypto.Cipher, opts ...Option) (*Store, error) {
	if pool == nil {
		return nil, errors.New("secrets: pool is nil")
	}
	if cipher == nil {
		return nil, errors.New("secrets: cipher is nil")
	}
	s := &Store{
		pool:       pool,
		cipher:     cipher,
		tenantKEK:  map[string]string{},
		kekClients: map[string]corecrypto.KMSClient{},
	}
	for _, opt := range opts {
		opt(s)
	}
	if err := s.initSchema(ctx); err != nil {
		return nil, fmt.Errorf("init schema: %w", err)
	}
	if err := s.loadTenantKEKCache(ctx); err != nil {
		return nil, fmt.Errorf("load tenant kms key overrides: %w", err)
	}
	return s, nil
}

func (s *Store) initSchema(ctx context.Context) error {
	schema := `
		CREATE TABLE IF NOT EXISTS secrets (
			id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			username     TEXT NOT NULL,
			name         TEXT NOT NULL,
			nonce        BYTEA NOT NULL,
			ciphertext   BYTEA NOT NULL,
			version      INT  NOT NULL DEFAULT 1,
			created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			UNIQUE (username, name)
		);

		-- Phase 4.1 Phase B (audit C-HIGH-6) — envelope encryption.
		-- Both nullable so the migration is non-destructive: pre-
		-- KMS rows keep wrapped_dek=NULL / kek_id=NULL and are
		-- decrypted via the legacy master-key path. New writes
		-- under KMS populate both columns.
		ALTER TABLE secrets ADD COLUMN IF NOT EXISTS wrapped_dek BYTEA;
		ALTER TABLE secrets ADD COLUMN IF NOT EXISTS kek_id      TEXT;

		-- Phase 4.3 Phase A — delivery mode column.
		-- "env" or "file"; defaults to "env" so pre-4.3 rows
		-- and any future row that omits the field behave
		-- exactly as before. Phase B switches the stamping
		-- code to honor this value.
		ALTER TABLE secrets ADD COLUMN IF NOT EXISTS delivery TEXT NOT NULL DEFAULT 'env';

		CREATE INDEX IF NOT EXISTS idx_secrets_username
			ON secrets(username);

		-- #1630 — per-tenant KEK overrides. One row per tenant that has
		-- opted into its own key; absence means the tenant is on the
		-- shared KEK. No soft-delete: clearing the override is a hard
		-- DELETE, matching org_encryption_settings-style tables — the
		-- audit log carries the durable history, not this row.
		CREATE TABLE IF NOT EXISTS tenant_kms_keys (
			username          TEXT PRIMARY KEY,
			kek_resource_name TEXT NOT NULL,
			created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
		);
	`
	_, err := s.pool.Exec(ctx, schema)
	return err
}

// Set creates or updates a secret. Idempotent — repeated calls with
// the same (username, name) bump the version and replace the
// ciphertext. Validates name + value at the API boundary before
// touching crypto or the DB.
//
// When the Store has a KMSClient configured (WithKMS), this writes
// an envelope row: a fresh per-row DEK encrypts the plaintext, the
// DEK is wrapped via the KMS, and wrapped_dek + kek_id are
// populated. Otherwise it writes a legacy row exactly as before
// Phase 4.1 — wrapped_dek and kek_id stay NULL.
//
// `delivery` (Phase 4.3) is one of "" (defaults to env on storage),
// "env", "file". Validated at the API boundary; invalid values
// reject before any DB work.
func (s *Store) Set(ctx context.Context, username, name, value, delivery string) (*SecretMetadata, error) {
	if username == "" {
		return nil, fmt.Errorf("username is required")
	}
	if err := corecrypto.ValidateName(name); err != nil {
		return nil, err
	}
	if err := corecrypto.ValidateValue(value); err != nil {
		return nil, err
	}
	if err := ValidateDelivery(delivery); err != nil {
		return nil, err
	}
	// compose delivery renders into a dotenv file; reject multi-line
	// values at set-time rather than silently corrupt it (#491).
	if err := ValidateValueForDelivery(delivery, value); err != nil {
		return nil, err
	}
	// Storage layer normalizes "" → "env" so the column is
	// always populated. Lets future migration code rely on
	// the field being non-empty.
	if delivery == "" {
		delivery = DeliveryEnv
	}

	nonce, ct, wrappedDEK, kekID, err := s.encryptForStorage(ctx, username, name, []byte(value))
	if err != nil {
		return nil, err
	}

	// INSERT ... ON CONFLICT DO UPDATE handles both create and
	// rotate in a single round-trip. The version bumps on every
	// rotation; the row's created_at stays as the original
	// (set-once-ever timestamp), updated_at moves to NOW().
	const q = `
		INSERT INTO secrets (username, name, nonce, ciphertext, wrapped_dek, kek_id, delivery, version)
		VALUES ($1, $2, $3, $4, $5, $6, $7, 1)
		ON CONFLICT (username, name)
		DO UPDATE SET
			nonce       = EXCLUDED.nonce,
			ciphertext  = EXCLUDED.ciphertext,
			wrapped_dek = EXCLUDED.wrapped_dek,
			kek_id      = EXCLUDED.kek_id,
			delivery    = EXCLUDED.delivery,
			version     = secrets.version + 1,
			updated_at  = NOW()
		RETURNING version, created_at, updated_at;
	`
	var version int32
	var createdAt, updatedAt time.Time
	if err := s.pool.QueryRow(ctx, q, username, name, nonce, ct, wrappedDEK, kekID, delivery).Scan(&version, &createdAt, &updatedAt); err != nil {
		return nil, fmt.Errorf("upsert secret: %w", err)
	}
	return &SecretMetadata{
		Username:  username,
		Name:      name,
		Version:   version,
		CreatedAt: createdAt,
		UpdatedAt: updatedAt,
		Delivery:  delivery,
	}, nil
}

// encryptForStorage picks the right encryption mode based on
// whether the Store has a KMSClient. Returns the row tuple to
// INSERT/UPDATE: (nonce, ciphertext, wrapped_dek_or_nil,
// kek_id_or_empty).
//
// Envelope path zeroes the DEK from memory before returning so
// the plaintext key doesn't outlive the function frame. The
// wrapped DEK is safe to hand back — it's encrypted under the
// KEK.
func (s *Store) encryptForStorage(ctx context.Context, username, name string, plaintext []byte) (nonce, ct, wrappedDEK []byte, kekID string, err error) {
	// #1630 — username's own KEK override if it has one, else the
	// shared/default s.kms (nil = legacy mode).
	kms, err := s.resolveEncryptKMS(username)
	if err != nil {
		return nil, nil, nil, "", fmt.Errorf("resolve kms for %s: %w", username, err)
	}
	if kms == nil {
		// Legacy mode: master-key encrypt directly.
		nonce, ct, err = s.cipher.Encrypt(username, name, plaintext)
		if err != nil {
			return nil, nil, nil, "", fmt.Errorf("encrypt (legacy): %w", err)
		}
		return nonce, ct, nil, "", nil
	}

	// Envelope mode: fresh DEK, encrypt under it, wrap the DEK.
	dek, err := corecrypto.NewDEK()
	if err != nil {
		return nil, nil, nil, "", fmt.Errorf("generate DEK: %w", err)
	}
	defer corecrypto.ZeroBytes(dek)

	dekCipher, err := corecrypto.NewCipher(dek)
	if err != nil {
		return nil, nil, nil, "", fmt.Errorf("build DEK cipher: %w", err)
	}
	nonce, ct, err = dekCipher.Encrypt(username, name, plaintext)
	if err != nil {
		return nil, nil, nil, "", fmt.Errorf("encrypt (envelope): %w", err)
	}

	wrappedDEK, kekID, err = kms.Wrap(ctx, dek)
	if err != nil {
		return nil, nil, nil, "", fmt.Errorf("KMS wrap: %w", err)
	}
	return nonce, ct, wrappedDEK, kekID, nil
}

// decryptFromStorage is the inverse — picks legacy vs envelope
// path based on whether wrapped_dek is populated. Zeros the DEK
// after use in the envelope branch.
//
// kms_id_check: if a row's kek_id doesn't match what the Store's
// KMSClient implementation expects (e.g. a row wrapped under
// "gcp-kms:..." reaching an InProcKMS-only daemon), the KMS
// returns an error from Unwrap — that's the signal a future
// daemon has been swapped to a different KMS without running the
// migration.
func (s *Store) decryptFromStorage(ctx context.Context, username, name string, nonce, ct, wrappedDEK []byte, kekID string) ([]byte, error) {
	// Legacy row: wrapped_dek IS NULL, kek_id IS NULL.
	if len(wrappedDEK) == 0 {
		if s.requireEnvelope {
			return nil, fmt.Errorf("secret %s/%s is legacy-encrypted but require_envelope=true (run `containarium secrets migrate-to-envelope` before retiring the master key)", username, name)
		}
		return s.cipher.Decrypt(username, name, nonce, ct)
	}
	// Envelope row. #1630 — resolved from the ROW's own kek_id, not
	// from any "current tenant override" state; see resolveDecryptKMS.
	kms, err := s.resolveDecryptKMS(kekID)
	if err != nil {
		return nil, fmt.Errorf("resolve kms for kek_id %q: %w", kekID, err)
	}
	if kms == nil {
		return nil, fmt.Errorf("secret %s/%s is envelope-encoded (kek_id=%q) but Store has no KMSClient configured", username, name, kekID)
	}
	dek, err := kms.Unwrap(ctx, wrappedDEK, kekID)
	if err != nil {
		return nil, fmt.Errorf("KMS unwrap: %w", err)
	}
	defer corecrypto.ZeroBytes(dek)
	dekCipher, err := corecrypto.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("build DEK cipher: %w", err)
	}
	return dekCipher.Decrypt(username, name, nonce, ct)
}

// resolveEncryptKMS picks the KMSClient a NEW Set for username should
// wrap under: username's per-tenant override if one is set (#1630),
// otherwise the shared/default s.kms (nil = legacy mode, unchanged
// behavior for every daemon that hasn't configured per-tenant keys).
func (s *Store) resolveEncryptKMS(username string) (corecrypto.KMSClient, error) {
	if s.tenantKMSFactory == nil {
		return s.kms, nil
	}
	s.tenantKEKMu.RLock()
	keyName, ok := s.tenantKEK[username]
	s.tenantKEKMu.RUnlock()
	if !ok {
		return s.kms, nil
	}
	return s.kekClient(keyName)
}

// resolveDecryptKMS picks the KMSClient that can unwrap a row whose
// kek_id is kekID. GCP rows are routed by the KEY NAME parsed out of
// kek_id, not by any "current tenant override" — every row decrypts
// under whatever key it actually says it's under, independent of
// whether SetTenantKMSKey/ClearTenantKMSKey has since moved that
// tenant's override elsewhere (or is still mid-rewrap). This is what
// makes a partially-completed rewrap safe: nothing here needs to know
// "am I done migrating this tenant yet."
//
// Non-GCP kek_ids (inproc/vault/aws) fall back to s.kms unchanged —
// per-tenant keys aren't implemented for those backends (#1630 scope).
func (s *Store) resolveDecryptKMS(kekID string) (corecrypto.KMSClient, error) {
	if s.tenantKMSFactory != nil {
		if keyName, ok := strings.CutPrefix(kekID, corecrypto.GCPKEKPrefix); ok {
			return s.kekClient(keyName)
		}
	}
	return s.kms, nil
}

// kekClient returns a cached KMSClient for keyResourceName, building
// one via tenantKMSFactory on first use. Shared by both the encrypt
// path (resolveEncryptKMS) and the decrypt path (resolveDecryptKMS) —
// a key that happens to be both "the shared default" and reached via
// this cache just means one harmless redundant client alongside s.kms,
// not an inconsistency.
func (s *Store) kekClient(keyResourceName string) (corecrypto.KMSClient, error) {
	s.kekClientsMu.RLock()
	c, ok := s.kekClients[keyResourceName]
	s.kekClientsMu.RUnlock()
	if ok {
		return c, nil
	}

	s.kekClientsMu.Lock()
	defer s.kekClientsMu.Unlock()
	if c, ok := s.kekClients[keyResourceName]; ok { // re-check post-lock
		return c, nil
	}
	built, err := s.tenantKMSFactory(keyResourceName)
	if err != nil {
		return nil, err
	}
	s.kekClients[keyResourceName] = built
	return built, nil
}

// loadTenantKEKCache populates tenantKEK from the tenant_kms_keys
// table once at Store construction, so resolveEncryptKMS is a pure
// in-memory lookup rather than a DB round-trip on every Set.
func (s *Store) loadTenantKEKCache(ctx context.Context) error {
	rows, err := s.pool.Query(ctx, `SELECT username, kek_resource_name FROM tenant_kms_keys`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var username, keyName string
		if err := rows.Scan(&username, &keyName); err != nil {
			return err
		}
		s.tenantKEK[username] = keyName
	}
	return rows.Err()
}

// SetTenantKMSKey sets username's per-tenant KEK to keyResourceName
// and re-wraps every secret username currently owns under it (#1630).
// Empty keyResourceName is equivalent to ClearTenantKMSKey.
//
// Requires the daemon's KMS backend to be "gcp" (WithTenantKMSFactory
// configured) — returns an error otherwise rather than silently
// no-op-ing what looks like a security-relevant change.
//
// The override is persisted and cached BEFORE the rewrap loop runs, so
// this is resumable: a retry after a partial failure only re-wraps
// rows still under their old key (each Get/Set pair is independently
// correct regardless of how many prior rows already moved — see
// resolveDecryptKMS).
func (s *Store) SetTenantKMSKey(ctx context.Context, username, keyResourceName string) error {
	username = strings.TrimSpace(username)
	if username == "" {
		return errors.New("secrets: username is required")
	}
	keyResourceName = strings.TrimSpace(keyResourceName)
	if keyResourceName == "" {
		return s.ClearTenantKMSKey(ctx, username)
	}
	if s.tenantKMSFactory == nil {
		return ErrTenantKMSNotSupported
	}
	if _, err := s.kekClient(keyResourceName); err != nil {
		return fmt.Errorf("build tenant kms client: %w", err)
	}

	const q = `
		INSERT INTO tenant_kms_keys (username, kek_resource_name)
		VALUES ($1, $2)
		ON CONFLICT (username) DO UPDATE SET
			kek_resource_name = EXCLUDED.kek_resource_name,
			updated_at        = NOW();
	`
	if _, err := s.pool.Exec(ctx, q, username, keyResourceName); err != nil {
		return fmt.Errorf("persist tenant kms key: %w", err)
	}
	s.tenantKEKMu.Lock()
	s.tenantKEK[username] = keyResourceName
	s.tenantKEKMu.Unlock()

	return s.rewrapTenant(ctx, username)
}

// ClearTenantKMSKey reverts username to the shared/default KEK,
// re-wrapping every secret they currently own back under it. Idempotent
// — clearing a tenant with no override just re-wraps (a no-op-shaped
// rewrap, since every row is already on the shared key) and succeeds.
func (s *Store) ClearTenantKMSKey(ctx context.Context, username string) error {
	username = strings.TrimSpace(username)
	if username == "" {
		return errors.New("secrets: username is required")
	}
	if _, err := s.pool.Exec(ctx, `DELETE FROM tenant_kms_keys WHERE username = $1`, username); err != nil {
		return fmt.Errorf("clear tenant kms key: %w", err)
	}
	s.tenantKEKMu.Lock()
	delete(s.tenantKEK, username)
	s.tenantKEKMu.Unlock()

	return s.rewrapTenant(ctx, username)
}

// rewrapTenant re-encrypts every secret username owns under whatever
// resolveEncryptKMS currently resolves for username — i.e., the
// override SetTenantKMSKey/ClearTenantKMSKey just committed.
//
// Not optimized to skip rows already on the target key — tenants carry
// a handful of secrets, not thousands, so a harmless re-encrypt of an
// already-correct row is an acceptable simplicity tradeoff here.
func (s *Store) rewrapTenant(ctx context.Context, username string) error {
	metas, err := s.List(ctx, username)
	if err != nil {
		return fmt.Errorf("list secrets for rewrap: %w", err)
	}
	for _, m := range metas {
		if err := s.rewrapOne(ctx, username, m.Name); err != nil {
			return fmt.Errorf("rewrap %s/%s: %w", username, m.Name, err)
		}
	}
	return nil
}

// rewrapMaxAttempts bounds rewrapOne's retry loop — generous for what
// should be, in practice, at most one real collision (a tenant setting
// a secret at the exact moment an admin rewraps their key).
const rewrapMaxAttempts = 5

// rewrapOne re-encrypts a single secret under the currently-resolved
// KMS client, via a version-guarded conditional UPDATE rather than
// Get-then-Set. A plain Get-then-Set is a read-modify-write race: if a
// tenant calls SetSecret on the same (username, name) between rewrapOne's
// read and write, the unconditional Set would silently overwrite the
// tenant's new value with the old plaintext re-encrypted, AND bump the
// version again — a silent rollback with no error anywhere (CodeRabbit
// finding on #1631). The conditional UPDATE affects zero rows if the
// version moved since the read; rewrapOne detects that and retries with
// a fresh read instead of clobbering.
//
// Preserves the row's version and delivery on success — a rewrap isn't
// a value change, so it shouldn't look like one (no version bump).
func (s *Store) rewrapOne(ctx context.Context, username, name string) error {
	for attempt := 0; attempt < rewrapMaxAttempts; attempt++ {
		meta, value, err := s.Get(ctx, username, name)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				return nil // deleted concurrently — nothing left to rewrap
			}
			return fmt.Errorf("read: %w", err)
		}
		nonce, ct, wrappedDEK, kekID, err := s.encryptForStorage(ctx, username, name, []byte(value))
		if err != nil {
			return fmt.Errorf("encrypt: %w", err)
		}
		ok, err := s.tryRewrapAtVersion(ctx, username, name, nonce, ct, wrappedDEK, kekID, meta.Version)
		if err != nil {
			return fmt.Errorf("write: %w", err)
		}
		if ok {
			return nil
		}
		// meta.Version no longer matches the row — something else
		// wrote (or deleted) it since the read above. Retry with a
		// fresh Get rather than overwrite whatever that write did.
	}
	return fmt.Errorf("gave up after %d attempts: concurrent writes to %s/%s kept racing the rewrap", rewrapMaxAttempts, username, name)
}

// tryRewrapAtVersion attempts the single conditional UPDATE rewrapOne
// needs, split out so it's testable without needing to actually win a
// race: a test can set up a row at version N, advance it to N+1 via an
// ordinary Set, and then assert that a rewrap attempt still targeting
// version N affects zero rows and leaves the N+1 row untouched.
func (s *Store) tryRewrapAtVersion(ctx context.Context, username, name string, nonce, ct, wrappedDEK []byte, kekID string, expectedVersion int32) (bool, error) {
	const q = `
		UPDATE secrets
		SET nonce = $1, ciphertext = $2, wrapped_dek = $3, kek_id = $4, updated_at = NOW()
		WHERE username = $5 AND name = $6 AND version = $7
	`
	tag, err := s.pool.Exec(ctx, q, nonce, ct, wrappedDEK, kekID, username, name, expectedVersion)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

// Get reads a single secret's decrypted plaintext value. Returns
// ErrNotFound if the (username, name) tuple isn't in the table.
//
// Failed decryption (wrong master key, tampered ciphertext) returns
// the underlying crypto error so callers can distinguish "you
// looked up something that exists but I can't decrypt it" from
// "nothing here."
//
// Phase B: envelope rows take the KMS-unwrap path; legacy rows
// (wrapped_dek IS NULL) take the master-key path. Both produce
// the same plaintext shape.
func (s *Store) Get(ctx context.Context, username, name string) (meta *SecretMetadata, value string, err error) {
	if username == "" {
		return nil, "", fmt.Errorf("username is required")
	}
	if verr := corecrypto.ValidateName(name); verr != nil {
		return nil, "", verr
	}

	const q = `
		SELECT nonce, ciphertext, wrapped_dek, kek_id, delivery, version, created_at, updated_at
		FROM secrets
		WHERE username = $1 AND name = $2
	`
	var nonce, ct, wrappedDEK []byte
	var kekID *string // nullable
	var delivery string
	var version int32
	var createdAt, updatedAt time.Time
	if err := s.pool.QueryRow(ctx, q, username, name).Scan(&nonce, &ct, &wrappedDEK, &kekID, &delivery, &version, &createdAt, &updatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, "", ErrNotFound
		}
		return nil, "", fmt.Errorf("select secret: %w", err)
	}

	kID := ""
	if kekID != nil {
		kID = *kekID
	}
	plaintext, err := s.decryptFromStorage(ctx, username, name, nonce, ct, wrappedDEK, kID)
	if err != nil {
		return nil, "", fmt.Errorf("decrypt secret: %w", err)
	}
	return &SecretMetadata{
		Username:  username,
		Name:      name,
		Version:   version,
		CreatedAt: createdAt,
		UpdatedAt: updatedAt,
		Delivery:  delivery,
	}, string(plaintext), nil
}

// List returns metadata for all secrets owned by the tenant.
// Values are never returned by this path — only Get returns the
// decrypted plaintext (and is audit-logged at the caller's layer).
func (s *Store) List(ctx context.Context, username string) ([]SecretMetadata, error) {
	if username == "" {
		return nil, fmt.Errorf("username is required")
	}
	const q = `
		SELECT username, name, version, created_at, updated_at, delivery
		FROM secrets
		WHERE username = $1
		ORDER BY name
	`
	rows, err := s.pool.Query(ctx, q, username)
	if err != nil {
		return nil, fmt.Errorf("list secrets: %w", err)
	}
	defer rows.Close()

	var out []SecretMetadata
	for rows.Next() {
		var m SecretMetadata
		if err := rows.Scan(&m.Username, &m.Name, &m.Version, &m.CreatedAt, &m.UpdatedAt, &m.Delivery); err != nil {
			return nil, fmt.Errorf("scan secret row: %w", err)
		}
		out = append(out, m)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate secret rows: %w", err)
	}
	return out, nil
}

// Delete removes a single secret. Returns ErrNotFound if no such
// row existed (so callers can return a clean 404 instead of a
// generic 200).
func (s *Store) Delete(ctx context.Context, username, name string) error {
	if username == "" {
		return fmt.Errorf("username is required")
	}
	if err := corecrypto.ValidateName(name); err != nil {
		return err
	}
	const q = `DELETE FROM secrets WHERE username = $1 AND name = $2`
	tag, err := s.pool.Exec(ctx, q, username, name)
	if err != nil {
		return fmt.Errorf("delete secret: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// UsernamesWithFileDelivery returns the set of tenants that
// own at least one file-mode secret. Used by the Phase 4.3
// reconciler to narrow the re-stamp pass to containers that
// could actually be affected by a bare `incus restart`
// (env-mode secrets survive the restart natively via incus
// config; only file-mode secrets need re-laying onto tmpfs).
//
// Empty result = no file-mode rows anywhere; the reconciler
// can no-op on the whole pass.
func (s *Store) UsernamesWithFileDelivery(ctx context.Context) ([]string, error) {
	const q = `
		SELECT DISTINCT username
		FROM secrets
		WHERE delivery = $1
		ORDER BY username
	`
	rows, err := s.pool.Query(ctx, q, DeliveryFile)
	if err != nil {
		return nil, fmt.Errorf("query file-mode tenants: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var u string
		if err := rows.Scan(&u); err != nil {
			return nil, fmt.Errorf("scan tenant: %w", err)
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// SecretValue pairs a decrypted plaintext with its delivery
// mode. Phase 4.3 — LoadAllForUserWithDelivery returns this
// so callers can dispatch per-secret (env stamp vs tmpfs
// file). Legacy LoadAllForUser keeps its name+value map
// shape for backwards compatibility.
type SecretValue struct {
	Value    string
	Delivery string
}

// LoadAllForUser returns the decrypted plaintext values for every
// secret owned by the tenant. Used by the daemon's env-var
// stamping path (CreateContainer / StartContainer / RefreshSecrets)
// to build the map of environment.<NAME>=<value> assignments.
//
// This path is the hot one: returning N decrypted values in one
// round-trip beats N Get calls. The caller is responsible for not
// logging the map or persisting it outside the LXC config.
//
// Phase B: per-row dispatch — legacy rows use master key, envelope
// rows use KMS unwrap. The mixed-state case (some of each) is
// supported until the migration tool runs.
//
// Phase 4.3 — backwards-compat shim. New callers should prefer
// LoadAllForUserWithDelivery to receive per-secret delivery
// modes and dispatch tmpfs / env stamping appropriately.
func (s *Store) LoadAllForUser(ctx context.Context, username string) (map[string]string, error) {
	full, err := s.LoadAllForUserWithDelivery(ctx, username)
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(full))
	for k, v := range full {
		out[k] = v.Value
	}
	return out, nil
}

// LoadAllForUserWithDelivery is the Phase 4.3 shape — same
// decrypt-all semantics as LoadAllForUser, but each entry
// carries the row's delivery mode so the caller can route
// "env" rows to incus config stamping and "file" rows to
// the tmpfs file writer.
//
// Rows with an empty / NULL delivery column (e.g. pre-4.3
// migrations missed by the DEFAULT 'env' clause) are
// treated as env.
func (s *Store) LoadAllForUserWithDelivery(ctx context.Context, username string) (map[string]SecretValue, error) {
	if username == "" {
		return nil, fmt.Errorf("username is required")
	}
	const q = `
		SELECT name, nonce, ciphertext, wrapped_dek, kek_id, delivery
		FROM secrets
		WHERE username = $1
	`
	rows, err := s.pool.Query(ctx, q, username)
	if err != nil {
		return nil, fmt.Errorf("load secrets for user: %w", err)
	}
	defer rows.Close()

	out := make(map[string]SecretValue)
	for rows.Next() {
		var name, delivery string
		var nonce, ct, wrappedDEK []byte
		var kekID *string
		if err := rows.Scan(&name, &nonce, &ct, &wrappedDEK, &kekID, &delivery); err != nil {
			return nil, fmt.Errorf("scan secret row: %w", err)
		}
		kID := ""
		if kekID != nil {
			kID = *kekID
		}
		pt, decErr := s.decryptFromStorage(ctx, username, name, nonce, ct, wrappedDEK, kID)
		if decErr != nil {
			return nil, fmt.Errorf("decrypt secret %s/%s: %w", username, name, decErr)
		}
		if delivery == "" {
			delivery = DeliveryEnv
		}
		out[name] = SecretValue{Value: string(pt), Delivery: delivery}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate secret rows: %w", err)
	}
	return out, nil
}
