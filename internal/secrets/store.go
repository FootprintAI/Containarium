// Package secrets implements the daemon-side Postgres-backed store
// for tenant secrets, layered on top of pkg/core/secrets crypto.
// See docs/SECRETS-MANAGEMENT-DESIGN.md.
package secrets

import (
	"context"
	"errors"
	"fmt"
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
)

// ValidateDelivery returns nil for "" (defaults to env at
// the storage layer), "env", or "file". Anything else is
// caller-error and rejected at the API boundary.
func ValidateDelivery(mode string) error {
	switch mode {
	case "", DeliveryEnv, DeliveryFile:
		return nil
	}
	return fmt.Errorf("secrets: delivery must be %q or %q; got %q",
		DeliveryEnv, DeliveryFile, mode)
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
}

// ErrNotFound is returned by Get / Delete when the (username, name)
// tuple has no row.
var ErrNotFound = errors.New("secrets: not found")

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
	s := &Store{pool: pool, cipher: cipher}
	for _, opt := range opts {
		opt(s)
	}
	if err := s.initSchema(ctx); err != nil {
		return nil, fmt.Errorf("init schema: %w", err)
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
	if s.kms == nil {
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

	wrappedDEK, kekID, err = s.kms.Wrap(ctx, dek)
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
	// Envelope row.
	if s.kms == nil {
		return nil, fmt.Errorf("secret %s/%s is envelope-encoded (kek_id=%q) but Store has no KMSClient configured", username, name, kekID)
	}
	dek, err := s.kms.Unwrap(ctx, wrappedDEK, kekID)
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
