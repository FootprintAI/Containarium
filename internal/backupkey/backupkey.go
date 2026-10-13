// Package backupkey holds the operator-side steps of a managed-key restore
// or verify (#2403), shared by `containarium backup restore|verify` and the
// MCP restore_backup / verify_backup tools so both run the same code:
// picking the newest record, and unwrapping a record's per-backup age
// identity under the caller's own KMS credentials. The daemon never
// unwraps; this runs in the operator's process, so KMS IAM decides who may
// decrypt and the KMS audit log records who did.
package backupkey

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/footprintai/containarium/pkg/core/secrets"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// KMSLoader builds the KMS client that can unwrap a key wrapped under
// kekID. It is the seam tests replace with a fake.
type KMSLoader func(kekID string) (secrets.KMSClient, error)

// operatorEnvHint is the setup an operator machine needs, named in every
// error that means "your KMS environment is not set up".
const operatorEnvHint = "set CONTAINARIUM_KMS_BACKEND=gcp and CONTAINARIUM_GCP_KMS_TOKEN=$(gcloud auth print-access-token) " +
	"(or CONTAINARIUM_GCP_KMS_TOKEN_FILE) so the unwrap runs under your own cloud identity"

// LoadOperatorKMS builds a KMS client from the caller's own environment
// for the CryptoKey named by a record's kek_id ("gcp:" + CryptoKeyVersion
// name). Only GCP managed keys exist today (#2402).
func LoadOperatorKMS(kekID string) (secrets.KMSClient, error) {
	keyName, ok := secrets.GCPCryptoKeyFromKEKID(kekID)
	if !ok {
		return nil, fmt.Errorf("kek_id %q is not a GCP KMS key version: only gcp managed keys can be unwrapped here", kekID)
	}
	c, err := LoadKMSClientForKey(keyName)
	if err != nil {
		return nil, fmt.Errorf("build your KMS client: %w; %s", err, operatorEnvHint)
	}
	return c, nil
}

// UnwrapIdentity unwraps rec's wrapped_key under its kek_id and returns
// the age identity ("AGE-SECRET-KEY-1..."). The caller owns the returned
// buffer and must zero it (secrets.ZeroBytes) once the request carrying it
// has been sent. A KMS refusal (PermissionDenied for a principal outside
// the decrypter role) is returned wrapped, before the caller has sent
// anything to the host.
func UnwrapIdentity(ctx context.Context, load KMSLoader, rec *pb.BackupRecord) ([]byte, error) {
	if len(rec.GetWrappedKey()) == 0 || rec.GetKekId() == "" {
		return nil, fmt.Errorf("backup %s has no managed key (no wrapped_key/kek_id on the record): restore it with its age identity file instead", rec.GetId())
	}
	kms, err := load(rec.GetKekId())
	if err != nil {
		return nil, err
	}
	identity, err := kms.Unwrap(ctx, rec.GetWrappedKey(), rec.GetKekId())
	if err != nil {
		return nil, fmt.Errorf("unwrap the key for backup %s under your KMS credentials: %w", rec.GetId(), err)
	}
	if !strings.HasPrefix(string(identity), "AGE-SECRET-KEY-1") {
		secrets.ZeroBytes(identity)
		return nil, fmt.Errorf("unwrapped key for backup %s is not an age identity", rec.GetId())
	}
	return identity, nil
}

// Newest returns the most recently created record for username and
// database. Both are required: "newest of anything" is a guess. A
// timestamp that does not parse, or two records sharing the newest one,
// is an error rather than an arbitrary pick.
func Newest(records []*pb.BackupRecord, username, database string) (*pb.BackupRecord, error) {
	if username == "" {
		return nil, fmt.Errorf("selecting the latest backup needs a user")
	}
	if database == "" {
		return nil, fmt.Errorf("selecting the latest backup needs a database")
	}
	var best *pb.BackupRecord
	var bestAt time.Time
	tie := false
	for _, r := range records {
		if r.GetUsername() != username || r.GetDatabase() != database {
			continue
		}
		at, err := time.Parse(time.RFC3339, r.GetCreatedAt())
		if err != nil {
			return nil, fmt.Errorf("backup %s: unparseable created_at %q: %w", r.GetId(), r.GetCreatedAt(), err)
		}
		switch {
		case best == nil || at.After(bestAt):
			best, bestAt, tie = r, at, false
		case at.Equal(bestAt):
			tie = true
		}
	}
	if best == nil {
		return nil, fmt.Errorf("no backup found for user %s, database %s", username, database)
	}
	if tie {
		return nil, fmt.Errorf("several backups for user %s, database %s have the same newest created_at %s: name one by id", username, database, best.GetCreatedAt())
	}
	return best, nil
}
