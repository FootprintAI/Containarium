package container

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
)

// SentinelKeyMarker is the comment line that flags the next line of a host
// authorized_keys file as the sentinel's upstream key. That key is
// platform-managed: ReplaceAuthorizedKeys always preserves it, so a caller
// replacing a box's keys cannot lock the sentinel (and so every inbound SSH
// session) out.
const SentinelKeyMarker = "# sshpiper sentinel upstream key"

// ValidateStrictSSHPublicKey is ValidateSSHPublicKey plus the checks a
// replace-all needs: the entry must be exactly one line holding a bare
// public key. authorized_keys options (command=, from=, no-pty, ...) are
// rejected, so a caller cannot smuggle a forced command or source filter
// into a key it does not own.
func ValidateStrictSSHPublicKey(key string) error {
	key = strings.TrimSpace(key)
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
// It returns the previously authorized caller-managed keys that are no
// longer present (by key material), so the caller can revoke them.
// Platform-managed keys are never in that list.
func ReplaceAuthorizedKeys(username string, keys []string) (removed []string, err error) {
	if !isValidUsername(username) {
		return nil, fmt.Errorf("invalid username: %s", username)
	}
	desired := make([]string, 0, len(keys))
	want := make(map[string]bool, len(keys))
	for i, k := range keys {
		k = strings.TrimSpace(k)
		if err := ValidateStrictSSHPublicKey(k); err != nil {
			return nil, fmt.Errorf("ssh_public_keys[%d]: %w", i, err)
		}
		mat, _ := keyMaterial(k)
		if want[mat] {
			continue
		}
		want[mat] = true
		desired = append(desired, k)
	}
	if !authorizedKeysUserExists(username) {
		return nil, fmt.Errorf("host user %q does not exist (was the container created?)", username)
	}

	sshDir := filepath.Join(authorizedKeysHomeRoot, username, ".ssh")
	akPath := filepath.Join(sshDir, "authorized_keys")
	// #nosec G304 -- akPath is a fixed suffix under the home root; username passed isValidUsername.
	existing, err := os.ReadFile(akPath)
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("read %s: %w", akPath, err)
	}

	// Split the current file into platform blocks (kept) and caller keys.
	var platform []string
	lines := strings.Split(string(existing), "\n")
	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == SentinelKeyMarker {
			j := i + 1
			for j < len(lines) && strings.TrimSpace(lines[j]) == "" {
				j++
			}
			platform = append(platform, SentinelKeyMarker)
			if j < len(lines) {
				platform = append(platform, strings.TrimSpace(lines[j]))
				i = j
			}
			continue
		}
		if mat, ok := keyMaterial(line); ok && !want[mat] {
			removed = append(removed, line)
		}
	}

	var out strings.Builder
	for _, k := range desired {
		out.WriteString(k + "\n")
	}
	if len(platform) > 0 {
		if len(desired) > 0 {
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
