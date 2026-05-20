package server

import (
	"fmt"
	"log"
	"os"
	"strings"
)

// Phase 4.7 — Postgres credential resolution from a
// secret-store source (audit C-MED-6).
//
// The audit flagged that the default Postgres password
// (`containarium`) lives in source and that operators have
// no first-class path to override it via a secret store.
// This file adds two narrow opt-ins, both mode-checked
// like the JWT token file landed in PR for Phase C-HIGH-7:
//
//   CONTAINARIUM_POSTGRES_URL_FILE
//     Full DSN in a single file. Highest precedence — when
//     set, the daemon and CLI use the file's contents
//     verbatim and ignore CONTAINARIUM_POSTGRES_URL.
//
//   CONTAINARIUM_POSTGRES_PASSWORD_FILE
//     Just the password in a single file. Useful when the
//     host/user/db are stable (auto-detect or operator
//     config) but the secret rotates.
//
// Both files are perm-checked: any non-owner read/write
// bit triggers a startup error. That keeps the audit
// contract from C-HIGH-7 consistent: anywhere we read a
// credential from disk, we refuse the world-readable
// case.

const (
	envPostgresURL          = "CONTAINARIUM_POSTGRES_URL"
	envPostgresURLFile      = "CONTAINARIUM_POSTGRES_URL_FILE"
	envPostgresPassword     = "CONTAINARIUM_POSTGRES_PASSWORD"
	envPostgresPasswordFile = "CONTAINARIUM_POSTGRES_PASSWORD_FILE"
)

// ResolvePostgresURL returns the full DSN to use. Search
// order:
//   1. CONTAINARIUM_POSTGRES_URL_FILE (perm-checked file
//      with a single-line DSN)
//   2. CONTAINARIUM_POSTGRES_URL (env var)
//   3. empty string (caller falls back to auto-detect)
//
// An unset / empty result is normal — the daemon's
// auto-detect path then assembles a DSN from the
// discovered Postgres container + a password resolved by
// ResolvePostgresPassword.
//
// Returns the DSN and a label for the audit log message
// ("file", "env", "auto-detect").
func ResolvePostgresURL() (dsn string, source string, err error) {
	if path := strings.TrimSpace(os.Getenv(envPostgresURLFile)); path != "" {
		b, err := readSecretFile(path, envPostgresURLFile)
		if err != nil {
			return "", "", err
		}
		return strings.TrimSpace(string(b)), "file:" + path, nil
	}
	if url := strings.TrimSpace(os.Getenv(envPostgresURL)); url != "" {
		return url, "env", nil
	}
	return "", "auto-detect", nil
}

// ResolvePostgresPassword returns the password to embed in
// an auto-assembled DSN. Search order:
//   1. CONTAINARIUM_POSTGRES_PASSWORD_FILE
//   2. CONTAINARIUM_POSTGRES_PASSWORD
//   3. DefaultPostgresPassword (with a WARNING log — the
//      compiled-in default is dev-only).
//
// Returns (password, source) so the caller can log the
// active source without leaking the password itself.
func ResolvePostgresPassword() (password string, source string, err error) {
	if path := strings.TrimSpace(os.Getenv(envPostgresPasswordFile)); path != "" {
		b, err := readSecretFile(path, envPostgresPasswordFile)
		if err != nil {
			return "", "", err
		}
		return strings.TrimSpace(string(b)), "file:" + path, nil
	}
	if pw := os.Getenv(envPostgresPassword); pw != "" {
		return pw, "env", nil
	}
	log.Printf("WARNING: Postgres password defaulting to the compiled-in dev value (%q). Set %s or %s for production.",
		DefaultPostgresPassword, envPostgresPassword, envPostgresPasswordFile)
	return DefaultPostgresPassword, "default", nil
}

// readSecretFile reads a credential file with the same
// perm contract as auth's readToken (PR #245 audit
// C-HIGH-7): mode must be ≤ 0600 (no non-owner bits).
// Returns the trimmed contents.
func readSecretFile(path, envName string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("%s=%s: stat: %w", envName, path, err)
	}
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		return nil, fmt.Errorf("%s=%s has insecure permissions %#o (any non-owner read/write bit set); chmod 0600 it", envName, path, mode)
	}
	b, err := os.ReadFile(path) // #nosec G304 -- path is operator config, already perm-checked
	if err != nil {
		return nil, fmt.Errorf("%s=%s: read: %w", envName, path, err)
	}
	return b, nil
}
