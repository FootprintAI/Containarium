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
//     holds the same public key cannot revoke the owner's entry. Ownership
//     compares user_id for an owner account (#3217), so a person's owner
//     account owns a row registered through their collaborator account;
//   - a revocation that would take effect is refused while another account
//     still holds the key in its own authorized_keys (#3222), so registering
//     someone else's key first does not let you revoke their access;
//   - an owner's refused revocation releases the row (#3217): it stays
//     active for the other holder but has no owner, so the next registration
//     takes it over, and a drop by an account no other account shares the
//     key with (the sole holder) revokes it.
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
	// ReleasedAt is when the owner dropped the key while another account
	// still held it (#3217). Zero = owned. A released row is still active.
	ReleasedAt time.Time
	Source     KeySource
}

// KeyLookup reads the registry.
type KeyLookup interface {
	Lookup(ctx context.Context, fingerprint string) (KeyRecord, error)
}

// KeyRegistry is what the daemon's key write paths need.
type KeyRegistry interface {
	Register(ctx context.Context, rec KeyRecord) error
	// Revoke revokes rec's fingerprint only when rec's account owns its row
	// or the row is released, and no other account holds the key.
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

// ErrNoHolderLookup is returned when a PGKeyStore has no HolderLookup. The
// lookup is what stops Revoke from revoking a key another account still
// holds (#3222), so a store without one is refused rather than run unguarded.
var ErrNoHolderLookup = errors.New("ssh key registry has no holder lookup")

// NewPGKeyStore creates the ssh_keys table if needed and returns the store.
// holders is required: Revoke uses it to refuse a revocation while another
// account still holds the key (#3222), and a nil lookup is an error here so
// no construction site can leave the guard off.
func NewPGKeyStore(ctx context.Context, pool *pgxpool.Pool, holders HolderLookup) (*PGKeyStore, error) {
	if pool == nil {
		return nil, errors.New("nil pool")
	}
	if holders == nil {
		return nil, ErrNoHolderLookup
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
		-- #3217, additive: NULL = owned. Reversible with
		-- ALTER TABLE ssh_keys DROP COLUMN released_at; an earlier binary
		-- ignores the column and treats a released row as its last owner's.
		ALTER TABLE ssh_keys ADD COLUMN IF NOT EXISTS released_at TIMESTAMPTZ;
	`
	if _, err := pool.Exec(ctx, schema); err != nil {
		return nil, fmt.Errorf("create ssh_keys: %w", err)
	}
	return &PGKeyStore{pool: pool, holders: holders}, nil
}

func nullTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	u := t.UTC()
	return &u
}

// Register records a key from a write path: first registration wins over an
// owned active row. A revoked row is replaced by this registration (new
// owner, source and created_at). A released row (#3217) is taken over: it
// gets this owner and source, and keeps its created_at, since the key was
// never revoked and its age stands.
func (s *PGKeyStore) Register(ctx context.Context, rec KeyRecord) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO ssh_keys (fingerprint, username, user_id, public_key, key_type, created_at, revoked_at, released_at, source)
		VALUES ($1, $2, $3, $4, $5, $6, NULL, NULL, $7)
		ON CONFLICT (fingerprint) DO UPDATE SET
			username    = EXCLUDED.username,
			user_id     = EXCLUDED.user_id,
			public_key  = EXCLUDED.public_key,
			key_type    = EXCLUDED.key_type,
			created_at  = CASE WHEN ssh_keys.revoked_at IS NOT NULL THEN EXCLUDED.created_at ELSE ssh_keys.created_at END,
			revoked_at  = NULL,
			released_at = NULL,
			source      = EXCLUDED.source
		WHERE ssh_keys.revoked_at IS NOT NULL OR ssh_keys.released_at IS NOT NULL`,
		rec.Fingerprint, rec.Username, rec.UserID, rec.PublicKey, rec.KeyType.String(), rec.CreatedAt.UTC(), string(rec.Source))
	if err != nil {
		return fmt.Errorf("register ssh key: %w", err)
	}
	return nil
}

// ownsRow reports whether rec's jump account owns cur. The same account
// always does. An owner account, whose user id is its own name, also owns a
// row registered through another jump account with the same user id
// (#3217): its collaborator account "<owner>-container-<user>" on someone
// else's box. A revoking login of the collaborator form matches by name
// only, because the user id it carries is the collaborator name a box owner
// chose, which the caller has not authenticated as.
func ownsRow(cur, rec KeyRecord) bool {
	if cur.Username == rec.Username {
		return true
	}
	return rec.UserID == rec.Username && cur.UserID == rec.UserID
}

// Revoke marks the key revoked when rec's account owns its row (#3187;
// ownership by user id, see ownsRow) or the row is released (#3217). A row
// another account owns is left unchanged: holding someone else's public key
// in your own authorized_keys does not let you revoke their entry; such a
// revoke returns nil and is logged. A key with no row gets a revoked row
// owned by rec.Username, so a later backfill cannot register it as live. An
// already revoked row keeps its original revocation time. The row is read
// and written in one transaction under a row lock, so the decision cannot
// race a concurrent registration.
//
// A revoke that would take effect is refused with ErrKeyHeldByOtherAccount
// while any other account still holds the key in its own authorized_keys
// (#3222). Ownership is first registration, and public keys are public, so
// the owner of a row can be the account that registered someone else's key
// first. The holder lookup reads the authorized_keys files, not the
// registry, because Register leaves an owned row alone for a later account
// and so records no second holder. When the refused caller owns the row, the
// row is released (#3217): it stays active for the other holder but no
// longer has an owner, so the dropper keeps no say over a key it no longer
// holds, the next registration takes the row over, and the sole remaining
// holder's own drop revokes it. A store without a HolderLookup fails Revoke
// with ErrNoHolderLookup, so nothing is released or revoked unguarded.
func (s *PGKeyStore) Revoke(ctx context.Context, rec KeyRecord, at time.Time) error {
	if s.holders == nil {
		return ErrNoHolderLookup
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("revoke ssh key: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	cur, err := lookupRow(ctx, tx, rec.Fingerprint, true)
	switch {
	case errors.Is(err, ErrKeyNotFound):
		if err := s.refuseIfHeldElsewhere(ctx, rec); err != nil {
			return err
		}
		// A registration that commits first wins: its row is the
		// registrant's, not this caller's.
		if _, err := tx.Exec(ctx, `
			INSERT INTO ssh_keys (fingerprint, username, user_id, public_key, key_type, created_at, revoked_at, source)
			VALUES ($1, $2, $3, $4, $5, $6, $6, $7)
			ON CONFLICT (fingerprint) DO NOTHING`,
			rec.Fingerprint, rec.Username, rec.UserID, rec.PublicKey, rec.KeyType.String(), at.UTC(), string(rec.Source)); err != nil {
			return fmt.Errorf("revoke ssh key: %w", err)
		}
	case err != nil:
		return fmt.Errorf("revoke ssh key: %w", err)
	case !cur.RevokedAt.IsZero():
		return nil // already revoked: keep the original revocation time
	case cur.ReleasedAt.IsZero() && !ownsRow(cur, rec):
		log.Printf("[ssh-keys] revoke by %s left %s active: its registry entry is owned by another account (#3187)",
			rec.Username, rec.Fingerprint)
		return nil
	default: // the caller owns an active row, or the row is released
		if err := s.refuseIfHeldElsewhere(ctx, rec); err != nil {
			if !errors.Is(err, ErrKeyHeldByOtherAccount) || !cur.ReleasedAt.IsZero() {
				return err
			}
			if _, uerr := tx.Exec(ctx, `UPDATE ssh_keys SET released_at = $2 WHERE fingerprint = $1`,
				rec.Fingerprint, at.UTC()); uerr != nil {
				return fmt.Errorf("release ssh key: %w", uerr)
			}
			if cerr := tx.Commit(ctx); cerr != nil {
				return fmt.Errorf("release ssh key: %w", cerr)
			}
			log.Printf("[ssh-keys] %s dropped %s while another account holds it: registry entry released and left active (#3217)",
				rec.Username, rec.Fingerprint)
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE ssh_keys SET revoked_at = $2 WHERE fingerprint = $1`,
			rec.Fingerprint, at.UTC()); err != nil {
			return fmt.Errorf("revoke ssh key: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("revoke ssh key: %w", err)
	}
	return nil
}

// refuseIfHeldElsewhere returns ErrKeyHeldByOtherAccount when another
// account than rec.Username holds the key. Revoke calls it only for a revoke
// that would take effect. The holders are compared by jump account, not user
// id: a person's other account still holding the key is a holder too.
func (s *PGKeyStore) refuseIfHeldElsewhere(ctx context.Context, rec KeyRecord) error {
	if s.holders == nil {
		return ErrNoHolderLookup
	}
	held, err := s.holders.OtherAccountHolds(ctx, rec.Fingerprint, rec.Username)
	if err != nil {
		return fmt.Errorf("revoke ssh key: holder lookup: %w", err)
	}
	if held {
		return ErrKeyHeldByOtherAccount
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
	return lookupRow(ctx, s.pool, fingerprint, false)
}

// rowQuerier is what lookupRow reads through: the pool or a transaction.
type rowQuerier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// lookupRow reads the row for fingerprint, locking it for the rest of the
// transaction when forUpdate is set.
func lookupRow(ctx context.Context, q rowQuerier, fingerprint string, forUpdate bool) (KeyRecord, error) {
	var (
		rec        KeyRecord
		keyType    string
		source     string
		revokedAt  *time.Time
		releasedAt *time.Time
	)
	query := `
		SELECT fingerprint, username, user_id, public_key, key_type, created_at, revoked_at, released_at, source
		FROM ssh_keys WHERE fingerprint = $1`
	if forUpdate {
		query += ` FOR UPDATE`
	}
	err := q.QueryRow(ctx, query, fingerprint).
		Scan(&rec.Fingerprint, &rec.Username, &rec.UserID, &rec.PublicKey, &keyType, &rec.CreatedAt, &revokedAt, &releasedAt, &source)
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
	if releasedAt != nil {
		rec.ReleasedAt = releasedAt.UTC()
	}
	return rec, nil
}
