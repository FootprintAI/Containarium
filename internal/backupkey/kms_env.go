package backupkey

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/footprintai/containarium/internal/config"
	"github.com/footprintai/containarium/pkg/core/secrets"
)

// LoadKMSClientForKey builds a GCP KMS client for one named CryptoKey from
// the KMS auth env (CONTAINARIUM_GCP_KMS_TOKEN or _TOKEN_FILE, optional
// _ENDPOINT and _TIMEOUT). It does not read CONTAINARIUM_GCP_KMS_KEY_NAME:
// on an operator machine the key comes from the backup record's kek_id,
// not from the daemon's shared KEK. The token is the caller's own
// (`gcloud auth print-access-token`), so every Decrypt is made, and
// audited, as that principal.
//
// Deliberately not internal/secrets.LoadTenantKMSFactory: that package
// links the Postgres store, which the containarium client must not carry.
func LoadKMSClientForKey(keyResourceName string) (secrets.KMSClient, error) {
	backend := strings.ToLower(strings.TrimSpace(os.Getenv(config.EnvKMSBackend)))
	if backend != "gcp" {
		return nil, fmt.Errorf("%s must be \"gcp\" (got %q)", config.EnvKMSBackend, backend)
	}
	cfg := secrets.GCPConfig{
		KeyName:   keyResourceName,
		Endpoint:  strings.TrimSpace(os.Getenv(config.EnvGCPKMSEndpoint)),
		Token:     strings.TrimSpace(os.Getenv(config.EnvGCPKMSToken)),
		TokenFile: strings.TrimSpace(os.Getenv(config.EnvGCPKMSTokenFile)),
	}
	if cfg.Token == "" && cfg.TokenFile == "" {
		return nil, fmt.Errorf("set either %s or %s", config.EnvGCPKMSToken, config.EnvGCPKMSTokenFile)
	}
	if t := strings.TrimSpace(os.Getenv(config.EnvGCPKMSTimeout)); t != "" {
		d, err := time.ParseDuration(t)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", config.EnvGCPKMSTimeout, err)
		}
		cfg.Timeout = d
	}
	return secrets.NewGCPKMS(cfg)
}
