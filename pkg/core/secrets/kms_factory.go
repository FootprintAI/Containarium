package secrets

import (
	"fmt"
	"os"
	"strings"
	"time"
)

// Phase 4.1 — KMS backend selector. Audit C-HIGH-6.
//
// The daemon and the migration CLI both need to build a
// KMSClient based on operator configuration. Centralizing
// the dispatch here means:
//
//   - One env-var contract for operators
//     (CONTAINARIUM_KMS_BACKEND=inproc|vault|none) instead
//     of every callsite re-implementing the switch.
//   - Future backends (GCP KMS, AWS KMS, …) slot in by
//     adding one case to this file; no daemon-startup or
//     CLI surgery.
//   - Misconfigurations surface as a single, descriptive
//     startup error.

// Recognized backend names. The default is "none" — no
// KMS configured, behavior identical to pre-Phase-4.1.
// Operators opt in by setting the env var.
const (
	KMSBackendNone   = "none"
	KMSBackendInProc = "inproc"
	KMSBackendVault  = "vault"
	KMSBackendGCP    = "gcp"
)

// LoadKMSClient picks a backend based on
// CONTAINARIUM_KMS_BACKEND and returns a constructed
// KMSClient plus a human-readable description for the
// startup log. Returns (nil, "disabled", nil) when the
// backend is "none" or the env var is unset.
//
// masterKey is the daemon's existing master key from
// LoadOrCreateMasterKey. The InProc backend wraps DEKs
// against it (cryptographically equivalent to legacy);
// other backends ignore it (Vault wraps via its
// KMS-resident Transit key).
func LoadKMSClient(masterKey []byte) (KMSClient, string, error) {
	backend := strings.ToLower(strings.TrimSpace(os.Getenv("CONTAINARIUM_KMS_BACKEND")))
	if backend == "" {
		backend = KMSBackendNone
	}
	switch backend {
	case KMSBackendNone, "off", "disabled":
		return nil, "disabled (CONTAINARIUM_KMS_BACKEND=none)", nil
	case KMSBackendInProc:
		k, err := NewInProcKMS(masterKey)
		if err != nil {
			return nil, "", fmt.Errorf("KMS backend inproc: %w", err)
		}
		return k, "inproc (master-key envelope, dev/test)", nil
	case KMSBackendVault:
		cfg, err := vaultConfigFromEnv()
		if err != nil {
			return nil, "", fmt.Errorf("KMS backend vault: %w", err)
		}
		k, err := NewVaultKMS(cfg)
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
		k, err := NewGCPKMS(cfg)
		if err != nil {
			return nil, "", fmt.Errorf("KMS backend gcp: %w", err)
		}
		return k, fmt.Sprintf("gcp cloud kms (key=%s)", cfg.KeyName), nil
	default:
		return nil, "", fmt.Errorf("KMS backend: unrecognized value %q (expected: none, inproc, vault, gcp)", backend)
	}
}

// vaultConfigFromEnv reads the Vault Transit config from
// env. Required: CONTAINARIUM_VAULT_ADDR,
// CONTAINARIUM_VAULT_TOKEN (or _TOKEN_FILE),
// CONTAINARIUM_VAULT_TRANSIT_KEY. Optional:
// CONTAINARIUM_VAULT_TRANSIT_MOUNT (default "transit"),
// CONTAINARIUM_VAULT_TIMEOUT (default 5s).
func vaultConfigFromEnv() (VaultConfig, error) {
	cfg := VaultConfig{
		Address: strings.TrimSpace(os.Getenv("CONTAINARIUM_VAULT_ADDR")),
		Mount:   strings.TrimSpace(os.Getenv("CONTAINARIUM_VAULT_TRANSIT_MOUNT")),
		KeyName: strings.TrimSpace(os.Getenv("CONTAINARIUM_VAULT_TRANSIT_KEY")),
	}
	if cfg.Address == "" {
		return cfg, fmt.Errorf("CONTAINARIUM_VAULT_ADDR is required")
	}
	if cfg.KeyName == "" {
		return cfg, fmt.Errorf("CONTAINARIUM_VAULT_TRANSIT_KEY is required")
	}

	// Token: env wins over file. Either is fine; file is
	// the recommended path for long-lived daemons (Vault
	// Agent writes a fresh token there and renews it).
	if tok := strings.TrimSpace(os.Getenv("CONTAINARIUM_VAULT_TOKEN")); tok != "" {
		cfg.Token = tok
	} else if path := strings.TrimSpace(os.Getenv("CONTAINARIUM_VAULT_TOKEN_FILE")); path != "" {
		tok, err := readBearerLikeFile(path)
		if err != nil {
			return cfg, fmt.Errorf("read CONTAINARIUM_VAULT_TOKEN_FILE: %w", err)
		}
		cfg.Token = tok
	}
	if cfg.Token == "" {
		return cfg, fmt.Errorf("set either CONTAINARIUM_VAULT_TOKEN or CONTAINARIUM_VAULT_TOKEN_FILE")
	}

	if t := strings.TrimSpace(os.Getenv("CONTAINARIUM_VAULT_TIMEOUT")); t != "" {
		d, err := time.ParseDuration(t)
		if err != nil {
			return cfg, fmt.Errorf("CONTAINARIUM_VAULT_TIMEOUT: %w", err)
		}
		cfg.Timeout = d
	}
	return cfg, nil
}

// gcpConfigFromEnv reads the Cloud KMS config from env.
// Required: CONTAINARIUM_GCP_KMS_KEY_NAME and one of
// CONTAINARIUM_GCP_KMS_TOKEN / _TOKEN_FILE. Optional:
// CONTAINARIUM_GCP_KMS_ENDPOINT (private-endpoint deployments
// override this), CONTAINARIUM_GCP_KMS_TIMEOUT (default 5s).
func gcpConfigFromEnv() (GCPConfig, error) {
	cfg := GCPConfig{
		KeyName:  strings.TrimSpace(os.Getenv("CONTAINARIUM_GCP_KMS_KEY_NAME")),
		Endpoint: strings.TrimSpace(os.Getenv("CONTAINARIUM_GCP_KMS_ENDPOINT")),
	}
	if cfg.KeyName == "" {
		return cfg, fmt.Errorf("CONTAINARIUM_GCP_KMS_KEY_NAME is required (e.g. projects/<p>/locations/<l>/keyRings/<r>/cryptoKeys/<k>)")
	}

	// Token: env wins over file. File is the recommended
	// long-lived path — a sidecar refreshes
	// `gcloud auth print-access-token` or hits the GCE
	// metadata server and writes the result atomically.
	if tok := strings.TrimSpace(os.Getenv("CONTAINARIUM_GCP_KMS_TOKEN")); tok != "" {
		cfg.Token = tok
	} else if path := strings.TrimSpace(os.Getenv("CONTAINARIUM_GCP_KMS_TOKEN_FILE")); path != "" {
		tok, err := readBearerLikeFile(path)
		if err != nil {
			return cfg, fmt.Errorf("read CONTAINARIUM_GCP_KMS_TOKEN_FILE: %w", err)
		}
		cfg.Token = tok
	}
	if cfg.Token == "" {
		return cfg, fmt.Errorf("set either CONTAINARIUM_GCP_KMS_TOKEN or CONTAINARIUM_GCP_KMS_TOKEN_FILE")
	}

	if t := strings.TrimSpace(os.Getenv("CONTAINARIUM_GCP_KMS_TIMEOUT")); t != "" {
		d, err := time.ParseDuration(t)
		if err != nil {
			return cfg, fmt.Errorf("CONTAINARIUM_GCP_KMS_TIMEOUT: %w", err)
		}
		cfg.Timeout = d
	}
	return cfg, nil
}

// readBearerLikeFile reads a credential file with the
// same perm contract as the JWT / Postgres secret files:
// mode must be ≤ 0600. Whitespace trimmed.
//
// Local helper so this file doesn't import the gateway/
// auth package. The contract is duplicated by intent —
// each secret-file reader stays self-contained.
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
