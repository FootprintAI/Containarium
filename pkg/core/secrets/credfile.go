package secrets

import (
	"fmt"
	"os"
	"strings"
)

// readBearerLikeFile reads a credential file with the same perm contract as the
// JWT / Postgres secret files: mode must be ≤ 0600. Whitespace trimmed.
//
// The GCP KMS backend re-reads its token file via this helper before each call
// so an out-of-band refresh takes effect without a daemon restart (#300). The
// app-layer KMS factory (internal/secrets) keeps its own copy for load-time
// resolution — the contract is duplicated by intent so each secret-file reader
// stays self-contained.
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
