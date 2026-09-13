package server

import (
	"context"
	"errors"
	"fmt"

	"github.com/footprintai/containarium/internal/secrets"
)

// backupAgeRecipientSecretName is the well-known tenant-secret name a
// tenant self-registers its backup age recipient under (#1836). It rides
// the existing Secrets API — versioned, audited, and eligible for a
// per-tenant KMS-backed KEK via SetTenantKMSKey — rather than a second,
// bespoke config store. The value is a PUBLIC key: storing it durably
// costs nothing in confidentiality, and doing so here means a scheduled
// backup needs no operator present to pass --age-recipient on every run.
// The matching PRIVATE identity must never be registered here, and never
// touches the platform — see docs/DB-BACKUP-OPERATIONS.md.
const backupAgeRecipientSecretName = "CONTAINARIUM_BACKUP_AGE_RECIPIENT" // #nosec G101 -- secret NAME, not a credential value

// secretsReader is the subset of *secrets.Store CreateBackup needs to
// resolve a tenant's registered recipient. A narrow interface — not the
// whole store — keeps resolveAgeRecipient unit-testable without a real
// Postgres + KMS backend.
type secretsReader interface {
	Get(ctx context.Context, username, name string) (*secrets.SecretMetadata, string, error)
}

// resolveAgeRecipient decides what age recipient (if any) a backup
// should be encrypted to (#1836):
//  1. explicit (the request's own age_recipient field) always wins — a
//     one-off call overrides whatever the tenant has registered.
//  2. otherwise, the tenant's own CONTAINARIUM_BACKUP_AGE_RECIPIENT
//     secret, if one is registered.
//  3. otherwise "" — plaintext, exactly today's default. Neither a
//     missing secrets store (standalone daemon) nor a tenant who never
//     registered one is an error.
//
// A store error that is NOT "not found" (e.g. KMS unavailable) DOES
// propagate — silently falling back to plaintext there would produce an
// unencrypted backup for a tenant who believes their key is enforced,
// which is a worse failure than refusing the backup.
func resolveAgeRecipient(ctx context.Context, store secretsReader, username, explicit string) (string, error) {
	if explicit != "" {
		return explicit, nil
	}
	if store == nil {
		return "", nil
	}
	_, value, err := store.Get(ctx, username, backupAgeRecipientSecretName)
	if err != nil {
		if errors.Is(err, secrets.ErrNotFound) {
			return "", nil
		}
		return "", fmt.Errorf("resolve tenant backup recipient: %w", err)
	}
	return value, nil
}

// backupSecretsReader adapts a ContainerServer's secrets store to
// secretsReader for CreateBackup, with one deliberate care: cs.secretsStore
// is a concrete *secrets.Store, nil on a standalone daemon. Returning it
// directly as a secretsReader would wrap a nil pointer in a non-nil
// interface value — resolveAgeRecipient's `store == nil` check would then
// miss it, and Get would nil-deref-panic on every plaintext backup on a
// standalone daemon. Compare the concrete pointer to nil BEFORE it
// crosses the interface boundary.
func backupSecretsReader(cs *ContainerServer) secretsReader {
	if cs.secretsStore == nil {
		return nil
	}
	return cs.secretsStore
}
