package secrets

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/footprintai/containarium/internal/config"
	corecrypto "github.com/footprintai/containarium/pkg/core/secrets"
)

// Phase 4.1 — KMS backend selector. Audit C-HIGH-6.
//
// The daemon and the migration CLI both need to build a KMSClient based on
// operator configuration. This factory lives in the app layer (not in
// pkg/core/secrets) so the core crypto package stays free of environment
// reading: it exposes only the typed *Config structs + constructors, and this
// file reads the environment (via internal/config name constants), resolves
// credential files, validates, and dispatches to the right backend.

// Recognized backend names. The default is "none" — no KMS configured, behavior
// identical to pre-Phase-4.1. Operators opt in by setting CONTAINARIUM_KMS_BACKEND.
const (
	KMSBackendNone   = "none"
	KMSBackendInProc = "inproc"
	KMSBackendVault  = "vault"
	KMSBackendGCP    = "gcp"
	KMSBackendAWS    = "aws"
)

// LoadKMSClient picks a backend based on CONTAINARIUM_KMS_BACKEND and returns a
// constructed KMSClient plus a human-readable description for the startup log.
// Returns (nil, "disabled", nil) when the backend is "none" or the env var is
// unset.
//
// masterKey is the daemon's existing master key from LoadOrCreateMasterKey. The
// InProc backend wraps DEKs against it (cryptographically equivalent to legacy);
// other backends ignore it (Vault wraps via its KMS-resident Transit key).
func LoadKMSClient(masterKey []byte) (corecrypto.KMSClient, string, error) {
	backend := strings.ToLower(strings.TrimSpace(os.Getenv(config.EnvKMSBackend)))
	if backend == "" {
		backend = KMSBackendNone
	}
	switch backend {
	case KMSBackendNone, "off", "disabled":
		return nil, "disabled (CONTAINARIUM_KMS_BACKEND=none)", nil
	case KMSBackendInProc:
		k, err := corecrypto.NewInProcKMS(masterKey)
		if err != nil {
			return nil, "", fmt.Errorf("KMS backend inproc: %w", err)
		}
		return k, "inproc (master-key envelope, dev/test)", nil
	case KMSBackendVault:
		cfg, err := vaultConfigFromEnv()
		if err != nil {
			return nil, "", fmt.Errorf("KMS backend vault: %w", err)
		}
		k, err := corecrypto.NewVaultKMS(cfg)
		if err != nil {
			return nil, "", fmt.Errorf("KMS backend vault: %w", err)
		}
		return k, fmt.Sprintf("vault transit (addr=%s mount=%s key=%s)",
			cfg.Address, cfg.Mount, cfg.KeyName), nil
	case KMSBackendGCP:
		cfg, err := gcpConfigFromEnv()
		if err != nil {
			return nil, "", fmt.Errorf("KMS backend gcp: %w", err)
		}
		k, err := corecrypto.NewGCPKMS(cfg)
		if err != nil {
			return nil, "", fmt.Errorf("KMS backend gcp: %w", err)
		}
		return k, fmt.Sprintf("gcp cloud kms (key=%s)", cfg.KeyName), nil
	case KMSBackendAWS:
		cfg, err := awsConfigFromEnv()
		if err != nil {
			return nil, "", fmt.Errorf("KMS backend aws: %w", err)
		}
		k, err := corecrypto.NewAWSKMS(cfg)
		if err != nil {
			return nil, "", fmt.Errorf("KMS backend aws: %w", err)
		}
		return k, fmt.Sprintf("aws kms (region=%s key=%s)", cfg.Region, cfg.KeyID), nil
	default:
		return nil, "", fmt.Errorf("KMS backend: unrecognized value %q (expected: none, inproc, vault, gcp, aws)", backend)
	}
}

// vaultConfigFromEnv reads the Vault Transit config from env. Required:
// CONTAINARIUM_VAULT_ADDR, CONTAINARIUM_VAULT_TOKEN (or _TOKEN_FILE),
// CONTAINARIUM_VAULT_TRANSIT_KEY. Optional: CONTAINARIUM_VAULT_TRANSIT_MOUNT
// (default "transit"), CONTAINARIUM_VAULT_TIMEOUT (default 5s).
func vaultConfigFromEnv() (corecrypto.VaultConfig, error) {
	cfg := corecrypto.VaultConfig{
		Address: strings.TrimSpace(os.Getenv(config.EnvVaultAddr)),
		Mount:   strings.TrimSpace(os.Getenv(config.EnvVaultTransitMount)),
		KeyName: strings.TrimSpace(os.Getenv(config.EnvVaultTransitKey)),
	}
	if cfg.Address == "" {
		return cfg, fmt.Errorf("CONTAINARIUM_VAULT_ADDR is required")
	}
	if cfg.KeyName == "" {
		return cfg, fmt.Errorf("CONTAINARIUM_VAULT_TRANSIT_KEY is required")
	}

	// Token: env wins over file. Either is fine; file is the recommended path for
	// long-lived daemons (Vault Agent writes a fresh token there and renews it).
	if tok := strings.TrimSpace(os.Getenv(config.EnvVaultToken)); tok != "" {
		cfg.Token = tok
	} else if path := strings.TrimSpace(os.Getenv(config.EnvVaultTokenFile)); path != "" {
		tok, err := readBearerLikeFile(path)
		if err != nil {
			return cfg, fmt.Errorf("read CONTAINARIUM_VAULT_TOKEN_FILE: %w", err)
		}
		cfg.Token = tok
	}
	if cfg.Token == "" {
		return cfg, fmt.Errorf("set either CONTAINARIUM_VAULT_TOKEN or CONTAINARIUM_VAULT_TOKEN_FILE")
	}

	if t := strings.TrimSpace(os.Getenv(config.EnvVaultTimeout)); t != "" {
		d, err := time.ParseDuration(t)
		if err != nil {
			return cfg, fmt.Errorf("CONTAINARIUM_VAULT_TIMEOUT: %w", err)
		}
		cfg.Timeout = d
	}
	return cfg, nil
}

// gcpConfigFromEnv reads the Cloud KMS config from env. Required:
// CONTAINARIUM_GCP_KMS_KEY_NAME and one of CONTAINARIUM_GCP_KMS_TOKEN /
// _TOKEN_FILE. Optional: CONTAINARIUM_GCP_KMS_ENDPOINT (private-endpoint
// deployments override this), CONTAINARIUM_GCP_KMS_TIMEOUT (default 5s).
func gcpConfigFromEnv() (corecrypto.GCPConfig, error) {
	cfg := corecrypto.GCPConfig{
		KeyName:  strings.TrimSpace(os.Getenv(config.EnvGCPKMSKeyName)),
		Endpoint: strings.TrimSpace(os.Getenv(config.EnvGCPKMSEndpoint)),
	}
	if cfg.KeyName == "" {
		return cfg, fmt.Errorf("CONTAINARIUM_GCP_KMS_KEY_NAME is required (e.g. projects/<p>/locations/<l>/keyRings/<r>/cryptoKeys/<k>)")
	}

	// Token source: a static token (CONTAINARIUM_GCP_KMS_TOKEN) or — recommended
	// for long-running daemons — a file (CONTAINARIUM_GCP_KMS_TOKEN_FILE) an
	// out-of-band sidecar refreshes (gcloud auth print-access-token / the GCE
	// metadata server, written atomically). The backend re-reads the file before
	// each call, so a refresh takes effect without a daemon restart. #300.
	cfg.Token = strings.TrimSpace(os.Getenv(config.EnvGCPKMSToken))
	cfg.TokenFile = strings.TrimSpace(os.Getenv(config.EnvGCPKMSTokenFile))
	if cfg.Token == "" && cfg.TokenFile == "" {
		return cfg, fmt.Errorf("set either CONTAINARIUM_GCP_KMS_TOKEN or CONTAINARIUM_GCP_KMS_TOKEN_FILE")
	}
	if cfg.TokenFile != "" {
		// Fail fast on an unreadable / insecurely-permissioned token file at
		// startup; the backend then re-reads it per call to honor refreshes.
		if _, err := readBearerLikeFile(cfg.TokenFile); err != nil {
			return cfg, fmt.Errorf("read CONTAINARIUM_GCP_KMS_TOKEN_FILE: %w", err)
		}
	}

	if t := strings.TrimSpace(os.Getenv(config.EnvGCPKMSTimeout)); t != "" {
		d, err := time.ParseDuration(t)
		if err != nil {
			return cfg, fmt.Errorf("CONTAINARIUM_GCP_KMS_TIMEOUT: %w", err)
		}
		cfg.Timeout = d
	}
	return cfg, nil
}

// awsConfigFromEnv reads the AWS KMS config from env. Required:
// CONTAINARIUM_AWS_KMS_REGION, CONTAINARIUM_AWS_KMS_KEY_ID,
// CONTAINARIUM_AWS_ACCESS_KEY_ID, and one of CONTAINARIUM_AWS_SECRET_ACCESS_KEY
// / _FILE. Optional: CONTAINARIUM_AWS_SESSION_TOKEN / _FILE (STS temp creds),
// CONTAINARIUM_AWS_KMS_ENDPOINT (VPC-endpoint / air-gapped deployments override
// this), CONTAINARIUM_AWS_KMS_TIMEOUT (default 5s).
func awsConfigFromEnv() (corecrypto.AWSConfig, error) {
	cfg := corecrypto.AWSConfig{
		Region:      strings.TrimSpace(os.Getenv(config.EnvAWSKMSRegion)),
		KeyID:       strings.TrimSpace(os.Getenv(config.EnvAWSKMSKeyID)),
		AccessKeyID: strings.TrimSpace(os.Getenv(config.EnvAWSAccessKeyID)),
		Endpoint:    strings.TrimSpace(os.Getenv(config.EnvAWSKMSEndpoint)),
	}
	if cfg.Region == "" {
		return cfg, fmt.Errorf("CONTAINARIUM_AWS_KMS_REGION is required")
	}
	if cfg.KeyID == "" {
		return cfg, fmt.Errorf("CONTAINARIUM_AWS_KMS_KEY_ID is required (key id, ARN, or alias/<name>)")
	}
	if cfg.AccessKeyID == "" {
		return cfg, fmt.Errorf("CONTAINARIUM_AWS_ACCESS_KEY_ID is required")
	}

	// Secret access key: env wins over file. File is the recommended long-lived
	// path — an IRSA / IMDS sidecar refreshes the credential and writes it
	// atomically.
	if sk := os.Getenv(config.EnvAWSSecretAccessKey); sk != "" {
		cfg.SecretAccessKey = sk
	} else if path := strings.TrimSpace(os.Getenv(config.EnvAWSSecretAccessKeyFile)); path != "" {
		sk, err := readBearerLikeFile(path)
		if err != nil {
			return cfg, fmt.Errorf("read CONTAINARIUM_AWS_SECRET_ACCESS_KEY_FILE: %w", err)
		}
		cfg.SecretAccessKey = sk
	}
	if cfg.SecretAccessKey == "" {
		return cfg, fmt.Errorf("set either CONTAINARIUM_AWS_SECRET_ACCESS_KEY or CONTAINARIUM_AWS_SECRET_ACCESS_KEY_FILE")
	}

	// Session token: optional (only for STS temp creds). Same env-wins-over-file
	// contract.
	if st := os.Getenv(config.EnvAWSSessionToken); st != "" {
		cfg.SessionToken = st
	} else if path := strings.TrimSpace(os.Getenv(config.EnvAWSSessionTokenFile)); path != "" {
		st, err := readBearerLikeFile(path)
		if err != nil {
			return cfg, fmt.Errorf("read CONTAINARIUM_AWS_SESSION_TOKEN_FILE: %w", err)
		}
		cfg.SessionToken = st
	}

	if t := strings.TrimSpace(os.Getenv(config.EnvAWSKMSTimeout)); t != "" {
		d, err := time.ParseDuration(t)
		if err != nil {
			return cfg, fmt.Errorf("CONTAINARIUM_AWS_KMS_TIMEOUT: %w", err)
		}
		cfg.Timeout = d
	}
	return cfg, nil
}

// readBearerLikeFile reads a credential file with the same perm contract as the
// JWT / Postgres secret files: mode must be ≤ 0600. Whitespace trimmed. The
// contract is duplicated by intent — each secret-file reader stays self-contained.
func readBearerLikeFile(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("stat %s: %w", path, err)
	}
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		return "", fmt.Errorf("%s has insecure permissions %#o (any non-owner read/write bit set); chmod 0600", path, mode)
	}
	b, err := os.ReadFile(path) // #nosec G304 -- operator-supplied, perm-checked
	if err != nil {
		return "", fmt.Errorf("read %s: %w", path, err)
	}
	s := strings.TrimSpace(string(b))
	if s == "" {
		return "", fmt.Errorf("%s is empty", path)
	}
	return s, nil
}
