package mcp

import (
	"log"
	"os"
	"strconv"

	"github.com/footprintai/containarium/internal/credentials"
)

// Config holds configuration for the MCP server
type Config struct {
	// ServerURL is the base URL of the Containarium REST API
	// Example: http://localhost:8080 or https://containarium.example.com
	ServerURL string

	// JWTToken is the JWT token for authentication. Either this or
	// JWTTokenFile must be set. JWTToken is captured once at MCP
	// server start; it can't reflect a rotation without a restart.
	// For long-running MCP processes that need to survive token
	// rotation, prefer JWTTokenFile.
	JWTToken string

	// JWTTokenFile, when set, points to a file containing the JWT
	// token. The file is re-read on every request to the Containarium
	// API, so rotating the token is a single `mv newtoken oldpath`
	// step — no MCP restart needed. Empty means use JWTToken instead.
	// Whitespace around the token in the file is trimmed.
	JWTTokenFile string

	// SentinelHost is the public SSH endpoint for the deployment.
	// When set, create_container's response includes a ready-to-paste
	// `ssh -i <key> <user>@<sentinel-host>` command — agents don't have
	// to figure out hostnames or modify ~/.ssh/config. Empty means
	// the response falls back to a placeholder.
	// Example: sentinel.example.com or 34.42.156.100
	SentinelHost string

	// Debug enables debug logging
	Debug bool
}

// LoadConfig loads configuration from environment variables, with a
// final fallback to ~/.containarium/credentials.json (the file
// `containarium login` writes — see internal/credentials). The
// precedence is, highest first:
//
//  1. CONTAINARIUM_JWT_TOKEN (static, in-process)
//  2. CONTAINARIUM_JWT_TOKEN_FILE (re-read per request — rotation-safe)
//  3. credentials.json lookup for ServerURL (or DefaultServer when
//     ServerURL is empty). Static for the life of the process —
//     prefer (2) when you need long-running token rotation.
//
// Fallback (3) is best-effort: any error reading credentials.json is
// logged + ignored, leaving JWTToken empty so the existing
// "missing token" message in cmd/mcp-server fires with full guidance.
// Logging lands on stderr (the MCP protocol owns stdout), so it
// never corrupts the JSON-RPC stream.
func LoadConfig() *Config {
	debug := false
	if debugStr := os.Getenv("CONTAINARIUM_DEBUG"); debugStr != "" {
		debug, _ = strconv.ParseBool(debugStr)
	}

	cfg := &Config{
		ServerURL:    os.Getenv("CONTAINARIUM_SERVER_URL"),
		JWTToken:     os.Getenv("CONTAINARIUM_JWT_TOKEN"),
		JWTTokenFile: os.Getenv("CONTAINARIUM_JWT_TOKEN_FILE"),
		SentinelHost: os.Getenv("CONTAINARIUM_SENTINEL_HOST"),
		Debug:        debug,
	}

	if cfg.JWTToken == "" && cfg.JWTTokenFile == "" {
		applyCredentialsFileFallback(cfg)
	}

	return cfg
}

// applyCredentialsFileFallback populates cfg.JWTToken (and ServerURL,
// when unset) from the user's ~/.containarium/credentials.json. A
// missing file or missing entry is silent — the existing env-var
// error message in cmd/mcp-server then surfaces with full guidance.
func applyCredentialsFileFallback(cfg *Config) {
	path, err := credentials.DefaultPath()
	if err != nil {
		// Home directory unresolvable — exotic env (no $HOME); leave
		// the env-var error to be the user's only signal.
		return
	}
	cf, err := credentials.Load(path)
	if err != nil {
		// Malformed / unreadable credentials file — log so the
		// operator sees it, but don't fail-stop; an explicit
		// env-var override may still be incoming via main.go's
		// startup check.
		log.Printf("[mcp-config] credentials.json at %s unreadable, ignoring: %v", path, err)
		return
	}
	creds, ok := cf.Get(cfg.ServerURL) // empty ServerURL → falls back to DefaultServer
	if !ok {
		return
	}
	cfg.JWTToken = creds.Token
	if cfg.ServerURL == "" {
		// User didn't pin a server; credentials.json's DefaultServer
		// answered the lookup, so adopt it as ServerURL too. Required
		// in the file's schema (Save enforces it's a key in Servers).
		cfg.ServerURL = cf.DefaultServer
	}
}
