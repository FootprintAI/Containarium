//go:build !windows

package cmd

import (
	"fmt"
	"log"

	"github.com/footprintai/containarium/internal/server"
)

// getPostgresConnString returns the PostgreSQL connection
// string from a secret-file / env / default chain.
//
// Phase 4.7 (audit C-MED-6): operators who don't want to
// bake the credential into the DSN env var can mount it
// through CONTAINARIUM_POSTGRES_URL_FILE (full DSN) or
// CONTAINARIUM_POSTGRES_PASSWORD_FILE (just the password,
// assembled into the legacy DSN shape below). Both files
// are mode-checked.
func getPostgresConnString() string {
	dsn, source, err := server.ResolvePostgresURL()
	if err != nil {
		log.Printf("ERROR: %v", err)
		return ""
	}
	if dsn != "" {
		log.Printf("[postgres] DSN source: %s", source)
		return dsn
	}

	// Fall back to the legacy in-cluster default with a
	// password resolved from a secret file / env / dev
	// default. The dev default surfaces a WARNING from
	// ResolvePostgresPassword.
	password, pwSource, err := server.ResolvePostgresPassword()
	if err != nil {
		log.Printf("ERROR: %v", err)
		return ""
	}
	log.Printf("[postgres] DSN source: auto-detect default, password source: %s", pwSource)
	return fmt.Sprintf("postgres://%s:%s@10.100.0.2:%d/%s?sslmode=disable",
		server.DefaultPostgresUser, password,
		server.DefaultPostgresPort, server.DefaultPostgresDB)
}
