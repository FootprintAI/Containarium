package sshauthz

// The ssh_keys registry (#2517; component 4 of the SSH live authorization
// design): fingerprint → who registered the key, when, and whether it has
// been revoked. It is the self-host authorization source the
// SelfHostDecider reads.
//
// Registration rules (decided on #2517):
//   - the registry is keyed by fingerprint alone;
//   - first registration wins: a write for a fingerprint that already has
//     an active row leaves that row unchanged;
//   - a write for a revoked fingerprint is a fresh registration: the row
//     takes the new owner, source and created_at, and revoked_at clears;
//   - a revocation applies only to the row the revoking account owns
//     (#3187, replacing #2517's "for every account"): another account that
//     holds the same public key cannot revoke the owner's entry.
//
// The backfill uses InsertIfAbsent instead, so a key revoked through the
// API but still present in another account's authorized_keys file is never
// made live again by a daemon restart.

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/ssh"

	"github.com/footprintai/containarium/internal/sshkey"
	"github.com/footprintai/containarium/pkg/core/container"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// KeySource records which write path registered a key.
type KeySource string

const (
	// SourceBoxCreate is a key passed with the box's create request.
	SourceBoxCreate KeySource = "box_create"
	// SourceAPI is a key added with AddSSHKey (`containarium container add-key`).
	SourceAPI KeySource = "api"
	// SourceCollaborator is a key added with AddCollaborator.
	SourceCollaborator KeySource = "collaborator"
	// SourceBackfill is a key found in an authorized_keys file at startup.
	SourceBackfill KeySource = "backfill"
)

// ErrKeyNotFound is returned by Lookup for a fingerprint with no row.
var ErrKeyNotFound = errors.New("ssh key not registered")

// KeyRecord is one ssh_keys row.
type KeyRecord struct {
	Fingerprint string // "SHA256:…", the ssh-keygen -l form
	Username    string // jump account the key was registered for
	UserID      string // UserIDForLogin(Username)
	PublicKey   string
	KeyType     pb.SSHKeyType
	CreatedAt   time.Time
	RevokedAt   time.Time // zero = active
	Source      KeySource
}

// KeyLookup reads the registry.
type KeyLookup interface {
	Lookup(ctx context.Context, fingerprint string) (KeyRecord, error)
}

// KeyRegistry is what the daemon's key write paths need.
type KeyRegistry interface {
	Register(ctx context.Context, rec KeyRecord) error
	// Revoke revokes rec's fingerprint only when rec.Username owns its row.
	Revoke(ctx context.Context, rec KeyRecord, at time.Time) error
}

// UserIDForLogin maps a jump account to the self-host user id: an owner
// account "<user>" is "<user>"; a collaborator account
// "<owner>-container-<collab>" is "<collab>" (decided on #2521).
func UserIDForLogin(login string) string {
	if c, ok := container.CollaboratorJumpAccountContainer(login); ok {
		return strings.TrimPrefix(login, c+"-")
	}
	return login
}

// NewKeyRecord builds the row for publicKey (an authorized_keys line,
// options allowed) registered to the jump account username at time at. The
// key must parse; its fingerprint and type are derived from it.
func NewKeyRecord(publicKey, username string, source KeySource, at time.Time) (KeyRecord, error) {
	publicKey = strings.TrimSpace(publicKey)
	pk, comment, _, _, err := ssh.ParseAuthorizedKey([]byte(publicKey))
	if err != nil {
		return KeyRecord{}, fmt.Errorf("parse public key: %w", err)
	}
	// Store the key itself, without any authorized_keys options.
	material := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pk)))
	if comment != "" {
		material += " " + comment
	}
	return KeyRecord{
		Fingerprint: ssh.FingerprintSHA256(pk), // same "SHA256:…" form as sshkey.Fingerprint
		Username:    username,
		UserID:      UserIDForLogin(username),
		PublicKey:   material,
		KeyType:     sshkey.ParseType(publicKey),
		CreatedAt:   at.UTC(),
		Source:      source,
	}, nil
}

// PGKeyStore is the Postgres-backed registry. It shares the daemon's pool
// with the collaborator store.
type PGKeyStore struct {
	pool    *pgxpool.Pool
	holders HolderLookup
}

// WithHolders sets the lookup Revoke uses to refuse a revocation while
// another account still holds the key (#3222).
func (s *PGKeyStore) WithHolders(h HolderLookup) *PGKeyStore {
	s.holders = h
	return s
}

// NewPGKeyStore creates the ssh_keys table if needed and returns the store.
func NewPGKeyStore(ctx context.Context, pool *pgxpool.Pool) (*PGKeyStore, error) {
	if pool == nil {
		return nil, errors.New("nil pool")
	}
	const schema = `
		CREATE TABLE IF NOT EXISTS ssh_keys (
			fingerprint TEXT PRIMARY KEY,
			username    TEXT NOT NULL,
			user_id     TEXT NOT NULL,
			public_key  TEXT NOT NULL,
			key_type    TEXT NOT NULL,
			created_at  TIMESTAMPTZ NOT NULL,
			revoked_at  TIMESTAMPTZ,
			source      TEXT NOT NULL
		);
		CREATE INDEX IF NOT EXISTS idx_ssh_keys_username ON ssh_keys(username);
	`
	if _, err := pool.Exec(ctx, schema); err != nil {
		return nil, fmt.Errorf("create ssh_keys: %w", err)
	}
	return &PGKeyStore{pool: pool}, nil
}

func nullTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	u := t.UTC()
	return &u
}

// Register records a key from a write path: first registration wins over an
// active row; a revoked row is replaced by this registration.
func (s *PGKeyStore) Register(ctx context.Context, rec KeyRecord) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO ssh_keys (fingerprint, username, user_id, public_key, key_type, created_at, revoked_at, source)
		VALUES ($1, $2, $3, $4, $5, $6, NULL, $7)
		ON CONFLICT (fingerprint) DO UPDATE SET
			username   = EXCLUDED.username,
			user_id    = EXCLUDED.user_id,
			public_key = EXCLUDED.public_key,
			key_type   = EXCLUDED.key_type,
			created_at = EXCLUDED.created_at,
			revoked_at = NULL,
			source     = EXCLUDED.source
		WHERE ssh_keys.revoked_at IS NOT NULL`,
		rec.Fingerprint, rec.Username, rec.UserID, rec.PublicKey, rec.KeyType.String(), rec.CreatedAt.UTC(), string(rec.Source))
	if err != nil {
		return fmt.Errorf("register ssh key: %w", err)
	}
	return nil
}

// Revoke marks the key revoked if rec.Username owns its row (#3187). A row
// registered by another account is left unchanged: holding someone else's
// public key in your own authorized_keys does not let you revoke their
// entry. The check is part of the upsert, so it cannot race a concurrent
// re-registration. A key with no row gets a revoked row owned by
// rec.Username, so a later backfill cannot register it as live. An already
// revoked row keeps its original revocation time. A revoke that changes no
// row (another account owns it) still returns nil and is logged.
func (s *PGKeyStore) Revoke(ctx context.Context, rec KeyRecord, at time.Time) error {
	tag, err := s.pool.Exec(ctx, `
		INSERT INTO ssh_keys (fingerprint, username, user_id, public_key, key_type, created_at, revoked_at, source)
		VALUES ($1, $2, $3, $4, $5, $6, $6, $7)
		ON CONFLICT (fingerprint) DO UPDATE SET
			revoked_at = COALESCE(ssh_keys.revoked_at, EXCLUDED.revoked_at)
		WHERE ssh_keys.username = EXCLUDED.username`,
		rec.Fingerprint, rec.Username, rec.UserID, rec.PublicKey, rec.KeyType.String(), at.UTC(), string(rec.Source))
	if err != nil {
		return fmt.Errorf("revoke ssh key: %w", err)
	}
	if tag.RowsAffected() == 0 {
		log.Printf("[ssh-keys] revoke by %s left %s active: its registry entry is owned by another account (#3187)",
			rec.Username, rec.Fingerprint)
	}
	return nil
}

// InsertIfAbsent writes rec only when no row exists for its fingerprint,
// active or revoked. It reports whether a row was inserted. Used by the
// backfill.
func (s *PGKeyStore) InsertIfAbsent(ctx context.Context, rec KeyRecord) (bool, error) {
	tag, err := s.pool.Exec(ctx, `
		INSERT INTO ssh_keys (fingerprint, username, user_id, public_key, key_type, created_at, revoked_at, source)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (fingerprint) DO NOTHING`,
		rec.Fingerprint, rec.Username, rec.UserID, rec.PublicKey, rec.KeyType.String(), rec.CreatedAt.UTC(), nullTime(rec.RevokedAt), string(rec.Source))
	if err != nil {
		return false, fmt.Errorf("insert ssh key: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// Lookup returns the row for fingerprint, or ErrKeyNotFound.
func (s *PGKeyStore) Lookup(ctx context.Context, fingerprint string) (KeyRecord, error) {
	var (
		rec       KeyRecord
		keyType   string
		source    string
		revokedAt *time.Time
	)
	err := s.pool.QueryRow(ctx, `
		SELECT fingerprint, username, user_id, public_key, key_type, created_at, revoked_at, source
		FROM ssh_keys WHERE fingerprint = $1`, fingerprint).
		Scan(&rec.Fingerprint, &rec.Username, &rec.UserID, &rec.PublicKey, &keyType, &rec.CreatedAt, &revokedAt, &source)
	if errors.Is(err, pgx.ErrNoRows) {
		return KeyRecord{}, ErrKeyNotFound
	}
	if err != nil {
		return KeyRecord{}, fmt.Errorf("lookup ssh key: %w", err)
	}
	rec.KeyType = pb.SSHKeyType(pb.SSHKeyType_value[keyType]) // unknown name → UNSPECIFIED
	rec.Source = KeySource(source)
	rec.CreatedAt = rec.CreatedAt.UTC()
	if revokedAt != nil {
		rec.RevokedAt = revokedAt.UTC()
	}
	return rec, nil
}
