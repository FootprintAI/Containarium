//go:build !containarium_client

package server

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/footprintai/containarium/internal/secrets"
	corecryptosecrets "github.com/footprintai/containarium/pkg/core/secrets"
)

// The tenant secrets store as a late-install family (#3327, on the #3326
// helper). The secret RPCs are registered unconditionally on
// ContainerServer and answer UNAVAILABLE while the store is nil; after a
// degraded start the helper installs it once Postgres answers, through the
// same open path boot uses, and swaps it in with SetSecretsStore.

const (
	// secretsStoreService is the family's grpc.health.v1 readiness entry.
	secretsStoreService = "containarium.secrets"
	secretsStoreDisplay = "tenant secrets store"
	// secretsMasterKeyPath is where the file-keyed master key lives; boot
	// and the late install load (or create) it from the same path.
	secretsMasterKeyPath = "/etc/containarium/secrets.key" // #nosec G101 -- the key FILE's path, not a credential value
)

// errSecretsEnvelopeWithoutKMS is the fail-closed refusal: the
// master-key retirement gate is on but no KMS backend is available.
var errSecretsEnvelopeWithoutKMS = errors.New("CONTAINARIUM_REQUIRE_ENVELOPE=true but no KMS backend is configured. Set CONTAINARIUM_KMS_BACKEND=vault (or inproc for dev) before enabling retirement mode. Secrets disabled")

// secretsStoreFamily is the helper registration for the secrets store:
// open it over the shared pool and swap it into cs. On error nothing is
// swapped in, so the RPCs keep answering UNAVAILABLE.
func secretsStoreFamily(cs *ContainerServer, open func(context.Context, *pgxpool.Pool) (*secrets.Store, error)) storeFamily {
	return storeFamily{
		Service: secretsStoreService,
		Display: secretsStoreDisplay,
		Install: func(ctx context.Context, pool *pgxpool.Pool) error {
			st, err := open(ctx, pool)
			if err != nil {
				return err
			}
			cs.SetSecretsStore(st)
			return nil
		},
	}
}

// openSecretsStore is the one open path for the secrets store, at boot and
// at late install: load or create the master key at keyPath, build the
// cipher, select the KMS backend from the environment, record the KMS
// status on cs, refuse when CONTAINARIUM_REQUIRE_ENVELOPE is set with no
// KMS, then open the store over pool. It never closes pool; on error the
// caller decides (boot closes its own pool, the helper keeps the shared
// one).
func openSecretsStore(ctx context.Context, pool *pgxpool.Pool, cs *ContainerServer, keyPath string) (*secrets.Store, error) {
	key, created, err := corecryptosecrets.LoadOrCreateMasterKey(keyPath)
	if err != nil {
		return nil, fmt.Errorf("load secrets master key: %w", err)
	}
	if created {
		log.Printf("[secrets] NEW MASTER KEY generated at %s — back this up off-host, losing it means every stored secret is unrecoverable ciphertext", keyPath)
	}
	cipher, err := corecryptosecrets.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("construct secrets cipher: %w", err)
	}
	// Phase 4.1 — KMS backend selection via env
	// CONTAINARIUM_KMS_BACKEND=none|inproc|vault. On err the store still
	// opens in legacy mode (no envelope) — operators see the WARNING rather
	// than the daemon refusing to start.
	kms, kdesc, kerr := secrets.LoadKMSClient(key)
	if kerr != nil {
		log.Printf("Warning: KMS backend config error: %v. Secrets store falling back to legacy mode.", kerr)
		kms = nil
		kdesc = "disabled (config error)"
	}
	// #1630 — per-tenant KEK factory, only non-nil when
	// CONTAINARIUM_KMS_BACKEND=gcp. A config error here degrades the SAME
	// way the shared client does: log and disable, don't fail the whole
	// secrets store over it.
	tenantKMSFactory, tkerr := secrets.LoadTenantKMSFactory()
	if tkerr != nil {
		log.Printf("Warning: per-tenant KMS factory config error: %v. SetTenantKMSKey will be unavailable.", tkerr)
		tenantKMSFactory = nil
	}
	// Phase 4.1 Phase-E — master-key retirement gate.
	// CONTAINARIUM_REQUIRE_ENVELOPE=true means every decrypt must go
	// through KMS; legacy rows are rejected. Refuse to wire the Store if the
	// gate is on but no KMS backend is configured — fail-closed is the only
	// safe shape.
	requireEnvelope := envBool("CONTAINARIUM_REQUIRE_ENVELOPE")
	// Snapshot KMS status for the KmsService GetKMSStatus RPC, regardless
	// of whether the store ends up wired (the status is about config, not
	// store health).
	cs.SetKMSStatus(os.Getenv("CONTAINARIUM_KMS_BACKEND"), kdesc, kms != nil, requireEnvelope)
	if requireEnvelope && kms == nil {
		return nil, errSecretsEnvelopeWithoutKMS
	}
	var opts []secrets.Option
	if kms != nil {
		opts = append(opts, secrets.WithKMS(kms))
	}
	if requireEnvelope {
		opts = append(opts, secrets.WithRequireEnvelope(true))
	}
	if tenantKMSFactory != nil {
		opts = append(opts, secrets.WithTenantKMSFactory(tenantKMSFactory))
	}
	store, err := secrets.NewStore(ctx, pool, cipher, opts...)
	if err != nil {
		return nil, fmt.Errorf("init secrets store: %w", err)
	}
	retirement := ""
	if requireEnvelope {
		retirement = " [legacy-rejected]"
	}
	log.Printf("Secrets store ready (file-keyed AES-256-GCM, envelope: %s%s)", kdesc, retirement)
	return store, nil
}

// notifySecrets is the notify service's live view of the secrets store.
// A nil *secrets.Store must stay a nil interface: the service then refuses
// tokens instead of dereferencing it.
func (s *ContainerServer) notifySecrets() notifySecretStore {
	if st := s.loadSecretsStore(); st != nil {
		return st
	}
	return nil
}
