package backup

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"path"
	"strings"

	"filippo.io/age"

	"github.com/footprintai/containarium/pkg/core/secrets"
)

// EngineHook marks a dump produced by a tenant-supplied backup hook
// (#1831): a byte stream the platform captured from the hook's stdout.
// Unless the hook declares its format (HookFormat, #2405) the daemon has
// no knowledge of it — it could be a pg_dump archive, a mysqldump,
// anything — so an opaque hook backup is stored, listed,
// integrity-checked, fetched and deleted, but never pg_restore'd.
const EngineHook = "hook"

// HookFormat is what a hook declares it emits (#2405). Kept as a string in
// the core, like Destination, so the package stays free of the pb
// dependency; the server maps it to/from pb.HookFormat.
//
// The declaration is a promise made by whoever configures the hook, not
// something the daemon checks when the backup is taken.
type HookFormat string

const (
	// HookFormatOpaque is an undeclared byte stream: stored, listed,
	// integrity-checked, fetched and deleted, never restored or
	// restore-tested by the platform. The default for a hook, and what a
	// hook record written before #2405 loads as.
	HookFormatOpaque HookFormat = "opaque"
	// HookFormatPGCustom is a `pg_dump -Fc` custom-format archive, the same
	// bytes database mode produces, so it can be restore-tested and
	// restored into a named target container.
	HookFormatPGCustom HookFormat = "pg_custom"
)

// validateHookFormat checks a requested format against the hook it
// describes: a format means nothing without a hook, and only the declared
// set is accepted. Empty is valid (it means opaque).
func validateHookFormat(format HookFormat, hookMode bool) error {
	switch format {
	case "":
		return nil
	case HookFormatOpaque, HookFormatPGCustom:
		if !hookMode {
			return fmt.Errorf("hook format %q applies only to a hook backup", format)
		}
		return nil
	default:
		return fmt.Errorf("unknown hook format %q (expected %q or %q)", format, HookFormatOpaque, HookFormatPGCustom)
	}
}

// countTOCTables counts the user tables a custom-format archive declares,
// from `pg_restore --list` output — the dump-side counterpart of
// userRelationQuery, so a pg_custom hook record gets the same manifest a
// database-mode record reads from the source catalog (#2405).
//
// A TOC entry line is "<dumpId>; <tableoid> <oid> <DESC> <schema> <name>
// <owner>", where DESC may be several words. Ordinary and partitioned
// tables are both "TABLE"; "TABLE DATA" and "TABLE ATTACH" are entries
// about a table, not tables, and FOREIGN TABLE / VIEW / SEQUENCE are not
// counted by userRelationQuery either. pg_dump never emits system
// catalogs, so no schema filter is needed.
func countTOCTables(toc string) int64 {
	var n int64
	for _, line := range strings.Split(toc, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, ";") {
			continue
		}
		semi := strings.Index(line, "; ")
		if semi < 0 {
			continue
		}
		// tableoid, oid, then DESC.
		fields := strings.Fields(line[semi+2:])
		if len(fields) < 4 || fields[2] != "TABLE" {
			continue
		}
		if fields[3] == "DATA" || fields[3] == "ATTACH" {
			continue
		}
		n++
	}
	return n
}

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

// wrapNewIdentity generates the ephemeral age identity for one managed
// backup (#2402) and hands its secret string to the wrapper. Only the
// public recipient and the wrapped bytes leave this function: the secret
// is zeroed before return, the identity object never escapes, and nothing
// is logged or written. The daemon itself cannot reverse the wrap — that
// is the whole point of an encrypt-only KMS binding.
func wrapNewIdentity(ctx context.Context, wrapper secrets.KMSClient) (recipient string, wrapped []byte, kekID string, err error) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		return "", nil, "", fmt.Errorf("generate backup identity: %w", err)
	}
	secret := []byte(id.String())
	defer secrets.ZeroBytes(secret)
	wrapped, kekID, err = wrapper.Wrap(ctx, secret)
	if err != nil {
		return "", nil, "", fmt.Errorf("wrap backup key: %w", err)
	}
	if len(wrapped) == 0 || kekID == "" {
		return "", nil, "", fmt.Errorf("wrap backup key: wrapper returned an empty wrapped key or kek id")
	}
	return id.Recipient().String(), wrapped, kekID, nil
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
