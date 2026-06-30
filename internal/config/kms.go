package config

// KMS / cloud-credential variable names. This namespace differs from the others
// in this package: its values are consumed inside pkg/core/secrets, which pulls
// in cloud provider SDKs. To keep internal/config lightweight (stdlib-only, so
// every importer stays cheap), config owns only the *names* here — the single
// source of truth for the namespace's identity. The read+resolve+validate
// factory that turns these into a KMS client lives in the app layer
// (internal/secrets.LoadKMSClient), where the SDK dependency already exists.
//
// Several names contain "secret"/"token"; gosec G101 flags constant identifiers
// like those assigned a string literal as "potential hardcoded credentials".
// These are env-var NAMES, not credentials, so each is annotated //nosec G101.
const (
	// KMS backend selector: none | inproc | vault | gcp | aws.
	EnvKMSBackend = "CONTAINARIUM_KMS_BACKEND"

	// AWS KMS.
	EnvAWSKMSRegion           = "CONTAINARIUM_AWS_KMS_REGION"
	EnvAWSKMSKeyID            = "CONTAINARIUM_AWS_KMS_KEY_ID"
	EnvAWSAccessKeyID         = "CONTAINARIUM_AWS_ACCESS_KEY_ID"
	EnvAWSKMSEndpoint         = "CONTAINARIUM_AWS_KMS_ENDPOINT"
	EnvAWSSecretAccessKey     = "CONTAINARIUM_AWS_SECRET_ACCESS_KEY"      // #nosec G101 -- env var name, not a credential value
	EnvAWSSecretAccessKeyFile = "CONTAINARIUM_AWS_SECRET_ACCESS_KEY_FILE" // #nosec G101 -- env var name, not a credential value
	EnvAWSSessionToken        = "CONTAINARIUM_AWS_SESSION_TOKEN"          // #nosec G101 -- env var name, not a credential value
	EnvAWSSessionTokenFile    = "CONTAINARIUM_AWS_SESSION_TOKEN_FILE"     // #nosec G101 -- env var name, not a credential value
	EnvAWSKMSTimeout          = "CONTAINARIUM_AWS_KMS_TIMEOUT"

	// Vault Transit.
	EnvVaultAddr         = "CONTAINARIUM_VAULT_ADDR"
	EnvVaultTransitMount = "CONTAINARIUM_VAULT_TRANSIT_MOUNT"
	EnvVaultTransitKey   = "CONTAINARIUM_VAULT_TRANSIT_KEY"
	EnvVaultToken        = "CONTAINARIUM_VAULT_TOKEN"      // #nosec G101 -- env var name, not a credential value
	EnvVaultTokenFile    = "CONTAINARIUM_VAULT_TOKEN_FILE" // #nosec G101 -- env var name, not a credential value
	EnvVaultTimeout      = "CONTAINARIUM_VAULT_TIMEOUT"

	// GCP Cloud KMS.
	EnvGCPKMSKeyName   = "CONTAINARIUM_GCP_KMS_KEY_NAME"
	EnvGCPKMSEndpoint  = "CONTAINARIUM_GCP_KMS_ENDPOINT"
	EnvGCPKMSToken     = "CONTAINARIUM_GCP_KMS_TOKEN"      // #nosec G101 -- env var name, not a credential value
	EnvGCPKMSTokenFile = "CONTAINARIUM_GCP_KMS_TOKEN_FILE" // #nosec G101 -- env var name, not a credential value
	EnvGCPKMSTimeout   = "CONTAINARIUM_GCP_KMS_TIMEOUT"
)
