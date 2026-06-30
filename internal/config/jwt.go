package config

// CONTAINARIUM_JWT_* variable names — REST/MCP bearer auth. The token names
// contain "secret"/"token"; gosec G101 flags such constant identifiers assigned
// a string literal, so each is annotated (they are env-var NAMES, not values).
const (
	EnvJWTSecret    = "CONTAINARIUM_JWT_SECRET"     // #nosec G101 -- env var name, not a credential value
	EnvJWTToken     = "CONTAINARIUM_JWT_TOKEN"      // #nosec G101 -- env var name, not a credential value
	EnvJWTTokenFile = "CONTAINARIUM_JWT_TOKEN_FILE" // #nosec G101 -- env var name, not a credential value
	EnvJWTAudience  = "CONTAINARIUM_JWT_AUDIENCE"
)

// JWT is the typed view of the CONTAINARIUM_JWT_* namespace.
type JWT struct {
	// Secret is the REST API's JWT signing secret (server side). (EnvJWTSecret)
	Secret string
	// Token is the bearer token a client presents. (EnvJWTToken)
	Token string
	// TokenFile is a file holding the bearer token (read by the client).
	// (EnvJWTTokenFile)
	TokenFile string
	// Audience is the expected `aud` claim. (EnvJWTAudience)
	Audience string
}

// LoadJWT reads the CONTAINARIUM_JWT_* namespace once.
func LoadJWT() JWT {
	return JWT{
		Secret:    getString(EnvJWTSecret, ""),
		Token:     getString(EnvJWTToken, ""),
		TokenFile: getString(EnvJWTTokenFile, ""),
		Audience:  getString(EnvJWTAudience, ""),
	}
}
