package backup

import (
	"bytes"
	"fmt"
	"io"
	"path"
	"strings"

	"filippo.io/age"
)

// EngineHook marks a dump produced by a tenant-supplied backup hook
// (#1831): an opaque byte stream the platform captured from the hook's
// stdout. The daemon has no knowledge of its format — it could be a
// pg_dump archive, a mysqldump, anything — so hook backups are stored,
// listed, integrity-checked, fetched and deleted, but never pg_restore'd.
const EngineHook = "hook"

// validateHook accepts only a bare absolute executable path inside the
// container. The hook is the tenant's own program; the platform runs it
// verbatim and reads its stdout. Arguments are refused so the value is a
// path, not a shell fragment — the path is single-quoted into the
// in-container command, never interpolated raw.
func validateHook(hook string) error {
	hook = strings.TrimSpace(hook)
	if hook == "" {
		return fmt.Errorf("backup hook is empty")
	}
	if !strings.HasPrefix(hook, "/") {
		return fmt.Errorf("backup hook must be an absolute path inside the container, got %q", hook)
	}
	if strings.ContainsAny(hook, " \t\r\n") {
		return fmt.Errorf("backup hook must be a bare executable path with no arguments, got %q", hook)
	}
	return nil
}

// hookLabel derives the record's "database" slot for a hook backup from
// the hook's basename (extension stripped), sanitized to the characters a
// backup id may carry. "/opt/backup/db-dump.sh" → "db-dump".
func hookLabel(hook string) string {
	base := path.Base(strings.TrimSpace(hook))
	// Strip from the first dot: "db-dump.sh" → "db-dump", and a dotfile
	// (".hidden") has no name worth keeping, so it falls through to "hook".
	if i := strings.Index(base, "."); i >= 0 {
		base = base[:i]
	}
	var b strings.Builder
	for _, r := range base {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	if b.Len() == 0 {
		return "hook"
	}
	return b.String()
}

// parseRecipient validates an age X25519 recipient ("age1…"). Only the
// holder of the matching identity can decrypt what is encrypted to it —
// the platform never holds that identity (#1831).
func parseRecipient(s string) (age.Recipient, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("age recipient is empty")
	}
	r, err := age.ParseX25519Recipient(s)
	if err != nil {
		return nil, fmt.Errorf("invalid age recipient %q: %w", s, err)
	}
	return r, nil
}

// encryptWithRecipient encrypts data to recipient entirely in memory. The
// caller stores the returned ciphertext; plaintext never reaches disk on
// the daemon host or any off-host store (#1831).
func encryptWithRecipient(data []byte, recipient string) ([]byte, error) {
	r, err := parseRecipient(recipient)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, r)
	if err != nil {
		return nil, fmt.Errorf("age encrypt: %w", err)
	}
	if _, err := w.Write(data); err != nil {
		return nil, fmt.Errorf("age encrypt: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("age encrypt: %w", err)
	}
	return buf.Bytes(), nil
}

// decryptWithIdentity decrypts an age ciphertext with an X25519 identity
// ("AGE-SECRET-KEY-1…") supplied by the caller for this one call. The
// identity is never persisted or logged.
func decryptWithIdentity(ciphertext []byte, identity string) ([]byte, error) {
	id, err := age.ParseX25519Identity(strings.TrimSpace(identity))
	if err != nil {
		return nil, fmt.Errorf("invalid age identity: %w", err)
	}
	r, err := age.Decrypt(bytes.NewReader(ciphertext), id)
	if err != nil {
		return nil, fmt.Errorf("age decrypt: %w", err)
	}
	pt, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("age decrypt: %w", err)
	}
	return pt, nil
}
