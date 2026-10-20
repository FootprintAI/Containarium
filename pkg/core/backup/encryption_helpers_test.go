package backup

import (
	"bytes"
	"filippo.io/age"
	"fmt"
	"io"
	"strings"
)

// encryptWithRecipients encrypts data to every recipient entirely in
// memory, as one age file any of them can open. The caller stores the
// returned ciphertext; plaintext never reaches disk on the daemon host or
// any off-host store (#1831). Two recipients — the per-backup managed
// identity and the tenant's legacy recipient — is how BOTH mode keeps the
// `.dump.age` format unchanged while either path can decrypt (#2402).
func encryptWithRecipients(data []byte, recipients ...string) ([]byte, error) {
	if len(recipients) == 0 {
		return nil, fmt.Errorf("age encrypt: no recipients")
	}
	rs := make([]age.Recipient, 0, len(recipients))
	for _, s := range recipients {
		r, err := parseRecipient(s)
		if err != nil {
			return nil, err
		}
		rs = append(rs, r)
	}
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, rs...)
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
