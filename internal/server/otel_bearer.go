package server

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Phase 2.5 follow-up — OTel collector bearer-token secret
// (audit C-HIGH-5, auth half).
//
// The collector's OTLP receivers are reachable from any
// monitoring=true container on the internal bridge. Today
// the receivers don't require auth — any process inside any
// monitoring container could push arbitrary spans / metrics
// pretending to be from a different container. The audit
// scoped the fix as a bearer-token check on every OTLP
// request.
//
// This file provides the primitive: a per-deployment shared
// secret that lives at `/etc/containarium/otel.bearer`,
// mode 0400, root-owned. Generated on first daemon startup
// and reused thereafter. The same pattern as the JWT secret
// file (PR for C-HIGH-7).
//
// The complete fix has two halves:
//
//   1. Daemon stamps `OTEL_EXPORTER_OTLP_HEADERS=Authorization=Bearer <secret>`
//      on every monitoring=true container so the OTel SDK
//      carries the credential. This file + the stamping
//      call in OTelEnvVarsForMigration are that half.
//
//   2. Collector config requires the bearer via the
//      `bearertokenauth` extension. The config-generation
//      change is a separate follow-up — the header is
//      harmless until the collector starts enforcing it,
//      so we can roll this half first without breakage.

const (
	otelBearerEnvOverride = "CONTAINARIUM_OTEL_BEARER"
	otelBearerEnvFile     = "CONTAINARIUM_OTEL_BEARER_FILE"
	otelBearerDefaultPath = "/etc/containarium/otel.bearer"

	// otelBearerSize is the random byte count for a newly
	// generated bearer. 32 bytes → 256 bits of entropy →
	// brute-force infeasible. Base64-encoded the token is
	// 44 characters, fits one line, no surprises in
	// Authorization headers.
	otelBearerSize = 32
)

var (
	otelBearerOnce  sync.Once
	otelBearerValue string
	otelBearerError error
)

// LoadOrCreateOTelBearer returns the deployment's OTel
// bearer secret. Search order:
//
//   1. `CONTAINARIUM_OTEL_BEARER` env var (raw value)
//   2. `CONTAINARIUM_OTEL_BEARER_FILE` env var → mode-
//      checked file with the secret
//   3. `/etc/containarium/otel.bearer` default path. If
//      the file exists, perm-checked and read; if not,
//      generated (mode 0600 owner-only) and persisted so
//      every subsequent call returns the same value.
//
// Returns ("", nil) when no source is available AND the
// daemon can't create the default file (read-only fs,
// insufficient perms, etc.). Callers downgrade gracefully
// — without the secret, the header isn't stamped and the
// collector stays open as before. This is the "rollout
// stayed safe" branch.
//
// Cached after the first call so the daemon and every
// monitoring=true container start hits the same value.
func LoadOrCreateOTelBearer() (string, error) {
	otelBearerOnce.Do(func() {
		otelBearerValue, otelBearerError = resolveOTelBearer()
	})
	return otelBearerValue, otelBearerError
}

func resolveOTelBearer() (string, error) {
	if v := strings.TrimSpace(os.Getenv(otelBearerEnvOverride)); v != "" {
		log.Printf("[otel-bearer] source: env %s", otelBearerEnvOverride)
		return v, nil
	}
	if path := strings.TrimSpace(os.Getenv(otelBearerEnvFile)); path != "" {
		v, err := readBearerFile(path, otelBearerEnvFile)
		if err != nil {
			return "", err
		}
		log.Printf("[otel-bearer] source: file %s", path)
		return v, nil
	}
	// Default path. Read if present; else generate and persist.
	if _, statErr := os.Stat(otelBearerDefaultPath); statErr == nil {
		v, err := readBearerFile(otelBearerDefaultPath, "default")
		if err != nil {
			return "", err
		}
		log.Printf("[otel-bearer] source: file %s (existing)", otelBearerDefaultPath)
		return v, nil
	}

	v, err := generateAndPersistBearer(otelBearerDefaultPath)
	if err != nil {
		log.Printf("[otel-bearer] WARNING: could not generate/persist bearer at %s: %v — header will NOT be stamped on monitoring containers; OTel collector remains open", otelBearerDefaultPath, err)
		return "", nil
	}
	log.Printf("[otel-bearer] source: file %s (newly generated, 0600)", otelBearerDefaultPath)
	return v, nil
}

func readBearerFile(path, source string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("otel bearer (%s) stat %s: %w", source, path, err)
	}
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		return "", fmt.Errorf("otel bearer file %s has insecure permissions %#o (any non-owner read/write bit set); chmod 0600 it", path, mode)
	}
	b, err := os.ReadFile(path) // #nosec G304 -- path is operator-supplied, perm-checked above
	if err != nil {
		return "", fmt.Errorf("otel bearer (%s) read %s: %w", source, path, err)
	}
	v := strings.TrimSpace(string(b))
	if v == "" {
		return "", fmt.Errorf("otel bearer file %s is empty", path)
	}
	return v, nil
}

// generateAndPersistBearer creates 32 random bytes, base64-
// encodes them, writes to `path` mode 0600. Path's parent
// must exist; if it doesn't, we don't `mkdir -p` because
// `/etc/containarium/` is operator-managed territory.
func generateAndPersistBearer(path string) (string, error) {
	if _, err := os.Stat(filepath.Dir(path)); err != nil {
		return "", fmt.Errorf("parent dir %s missing: %w", filepath.Dir(path), err)
	}
	var b [otelBearerSize]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("read random: %w", err)
	}
	token := base64.RawStdEncoding.EncodeToString(b[:])
	if err := os.WriteFile(path, []byte(token+"\n"), 0o600); err != nil {
		return "", fmt.Errorf("write %s: %w", path, err)
	}
	return token, nil
}
