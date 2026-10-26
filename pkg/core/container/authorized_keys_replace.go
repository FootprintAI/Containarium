package container

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"
)

// SentinelKeyMarker is the comment line that flags the next line of a host
// authorized_keys file as the sentinel's upstream key. That key is
// platform-managed: ReplaceAuthorizedKeys always preserves it, so a caller
// replacing a box's keys cannot lock the sentinel (and so every inbound SSH
// session) out.
const SentinelKeyMarker = "# sshpiper sentinel upstream key"

// Bounds on a replace-all so a caller cannot make the daemon rewrite an
// arbitrarily large file.
const (
	MaxAuthorizedKeys     = 100
	MaxAuthorizedKeyBytes = 8 * 1024
)

// authorizedKeysLocks serializes every read-modify-write of one user's host
// authorized_keys (Add, Remove, Replace), so a concurrent Add cannot be lost
// to a Replace's rename or the reverse. The daemon is a single process, so a
// process-local mutex is enough.
var authorizedKeysLocks sync.Map // username -> *sync.Mutex

func lockAuthorizedKeys(username string) (unlock func()) {
	m, _ := authorizedKeysLocks.LoadOrStore(username, &sync.Mutex{})
	mu := m.(*sync.Mutex)
	mu.Lock()
	return mu.Unlock
}

// canonicalKeyLine regenerates the line written for a validated key from its
// parsed form, never from the caller's text: "<type> <base64>" plus the
// comment reduced to a safe charset (anything else becomes "_", so no
// whitespace, '#', control characters or shell metacharacters survive).
func canonicalKeyLine(key string) (line, material string, err error) {
	pk, comment, _, _, err := ssh.ParseAuthorizedKey([]byte(key))
	if err != nil {
		return "", "", fmt.Errorf("not a valid SSH public key: %w", err)
	}
	material = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pk)))
	var c strings.Builder
	for _, r := range comment {
		if c.Len() >= 64 {
			break
		}
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '@', r == '.', r == '_', r == '-', r == '+', r == '=', r == ':', r == '/':
			c.WriteRune(r)
		default:
			c.WriteByte('_')
		}
	}
	if c.Len() == 0 {
		return material, material, nil
	}
	return material + " " + c.String(), material, nil
}

// ValidateStrictSSHPublicKey is ValidateSSHPublicKey plus the checks a
// replace-all needs: the entry must be exactly one line holding a bare
// public key. authorized_keys options (command=, from=, no-pty, ...) are
// rejected, so a caller cannot smuggle a forced command or source filter
// into a key it does not own.
func ValidateStrictSSHPublicKey(key string) error {
	key = strings.TrimSpace(key)
	if len(key) > MaxAuthorizedKeyBytes {
		return fmt.Errorf("key is %d bytes, over the %d byte limit", len(key), MaxAuthorizedKeyBytes)
	}
	if err := ValidateSSHPublicKey(key); err != nil {
		return err
	}
	_, _, opts, _, err := ssh.ParseAuthorizedKey([]byte(key))
	if err != nil {
		return fmt.Errorf("not a valid SSH public key: %w", err)
	}
	if len(opts) > 0 {
		return fmt.Errorf("key has authorized_keys options (%s); only bare public keys are accepted", strings.Join(opts, ","))
	}
	return nil
}

// keyMaterial returns the "<type> <base64>" identity of an authorized_keys
// line, ignoring options and comment.
func keyMaterial(line string) (string, bool) {
	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pk))), true
}

// ReplaceAuthorizedKeys makes the host-side
// /home/<username>/.ssh/authorized_keys hold exactly keys, in the given
// order with duplicates collapsed, plus every platform-managed block
// (SentinelKeyMarker and the key line after it), which is carried over
// untouched. Every key is validated before anything is written, so a bad
// entry fails the whole call and leaves the file as it was. The write is
// atomic (temp file + rename), and replacing with the keys already present
// rewrites identical content.
//
// The file is rewritten, not edited: each kept key is written as a regenerated
// canonical line (see canonicalKeyLine), and comment lines, unparseable lines
// and option-bearing legacy lines that are not in the new set are dropped.
//
// beforeWrite, when non-nil, is called with the caller-managed keys about to
// be dropped (by key material; platform keys are never in the list) after the
// file has been read and before anything is written. If it fails, nothing is
// written and its error is returned, so a retry sees the same keys. That lets
// the caller revoke them first, failing closed. It runs under the per-user
// lock, so it must not call back into this package for the same user.
// The same list is returned.
func ReplaceAuthorizedKeys(username string, keys []string, beforeWrite func(removed []string) error) (removed []string, err error) {
	if !isValidUsername(username) {
		return nil, fmt.Errorf("invalid username: %s", username)
	}
	if len(keys) > MaxAuthorizedKeys {
		return nil, fmt.Errorf("%d keys given, over the limit of %d", len(keys), MaxAuthorizedKeys)
	}
	type wanted struct{ line, material string }
	var desired []wanted
	want := make(map[string]bool, len(keys))
	for i, k := range keys {
		k = strings.TrimSpace(k)
		if err := ValidateStrictSSHPublicKey(k); err != nil {
			return nil, fmt.Errorf("ssh_public_keys[%d]: %w", i, err)
		}
		line, mat, err := canonicalKeyLine(k)
		if err != nil {
			return nil, fmt.Errorf("ssh_public_keys[%d]: %w", i, err)
		}
		if want[mat] {
			continue
		}
		want[mat] = true
		desired = append(desired, wanted{line, mat})
	}
	if !authorizedKeysUserExists(username) {
		return nil, fmt.Errorf("host user %q does not exist (was the container created?)", username)
	}

	defer lockAuthorizedKeys(username)()

	sshDir := filepath.Join(authorizedKeysHomeRoot, username, ".ssh")
	akPath := filepath.Join(sshDir, "authorized_keys")
	// #nosec G304 -- akPath is a fixed suffix under the home root; username passed isValidUsername.
	existing, err := os.ReadFile(akPath)
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("read %s: %w", akPath, err)
	}

	// Pass 1: collect the platform blocks (kept) and their key material, so
	// a caller line that duplicates a platform key is recognised wherever it
	// sits in the file. Pass 2: everything else that parses is a caller key.
	var platform []string
	platformMat := map[string]bool{}
	platformLine := map[int]bool{}
	lines := strings.Split(string(existing), "\n")
	for i := 0; i < len(lines); i++ {
		if strings.TrimSpace(lines[i]) != SentinelKeyMarker {
			continue
		}
		platformLine[i] = true
		platform = append(platform, SentinelKeyMarker)
		j := i + 1
		for j < len(lines) && strings.TrimSpace(lines[j]) == "" {
			j++
		}
		if j < len(lines) {
			kl := strings.TrimSpace(lines[j])
			platform = append(platform, kl)
			if m, ok := keyMaterial(kl); ok {
				platformMat[m] = true
			}
			platformLine[j] = true
			i = j
		}
	}
	for i, raw := range lines {
		if platformLine[i] {
			continue
		}
		line := strings.TrimSpace(raw)
		if mat, ok := keyMaterial(line); ok && !want[mat] && !platformMat[mat] {
			removed = append(removed, line)
		}
	}

	if beforeWrite != nil {
		if err := beforeWrite(removed); err != nil {
			return nil, err
		}
	}

	var out strings.Builder
	written := 0
	for _, k := range desired {
		if platformMat[k.material] {
			continue // already kept by the platform block
		}
		out.WriteString(k.line + "\n")
		written++
	}
	if len(platform) > 0 {
		if written > 0 {
			out.WriteString("\n")
		}
		out.WriteString(strings.Join(platform, "\n") + "\n")
	}

	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		return nil, fmt.Errorf("mkdir %s: %w", sshDir, err)
	}
	tmp, err := os.CreateTemp(sshDir, ".authorized_keys.tmp.*")
	if err != nil {
		return nil, fmt.Errorf("create temp: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return nil, fmt.Errorf("chmod tmp: %w", err)
	}
	if _, err := tmp.WriteString(out.String()); err != nil {
		_ = tmp.Close()
		return nil, fmt.Errorf("write tmp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return nil, fmt.Errorf("sync tmp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return nil, fmt.Errorf("close tmp: %w", err)
	}
	if err := os.Rename(tmpPath, akPath); err != nil {
		return nil, fmt.Errorf("rename tmp -> %s: %w", akPath, err)
	}
	// Best-effort, as in AddAuthorizedKey.
	// #nosec G204 -- username passed isValidUsername; the command is fixed.
	_ = exec.Command("chown", "-R", username+":"+username, sshDir).Run()
	return removed, nil
}
