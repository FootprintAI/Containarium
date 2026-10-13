package sshkey

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// GenerateFresh creates a distinct keypair without replacing previous keys.
func GenerateFresh(opts LocateOpts) (pubPath, pub string, err error) {
	return generate(opts, false, containariumKeyName+"_"+rand.Text())
}

// RemoveRetired removes only CLI-owned keypairs explicitly retired by the
// server. Personal keys and unknown or merely expired keys are retained.
func RemoveRetired(opts LocateOpts, keys []SSHKey, now time.Time) ([]string, error) {
	retired, active := make(map[string]bool), make(map[string]bool)
	for _, key := range keys {
		if key.Fingerprint == "" {
			continue
		}
		if key.RetiredAt != nil && !key.RetiredAt.IsZero() && !key.RetiredAt.After(now) {
			retired[key.Fingerprint] = true
		} else {
			active[key.Fingerprint] = true
		}
	}
	dir, err := sshDir(opts.HomeDir)
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var removed []string
	for _, entry := range entries {
		name := entry.Name()
		if !entry.Type().IsRegular() || !strings.HasSuffix(name, ".pub") || (name != containariumKeyName+".pub" && !strings.HasPrefix(name, containariumKeyName+"_")) {
			continue
		}
		pubPath := filepath.Join(dir, name)
		pub, err := ReadPublicKey(pubPath)
		if err != nil {
			continue
		}
		fp, err := Fingerprint(pub)
		if err != nil || !retired[fp] || active[fp] {
			continue
		}
		path := strings.TrimSuffix(pubPath, ".pub")
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		key, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		signer, err := ssh.ParsePrivateKey(key)
		if err != nil || ssh.FingerprintSHA256(signer.PublicKey()) != fp {
			continue
		}
		if err := os.Remove(path); err != nil {
			return removed, fmt.Errorf("remove retired key: %w", err)
		}
		removed = append(removed, path)
		if err := os.Remove(pubPath); err != nil {
			return removed, fmt.Errorf("remove retired public key: %w", err)
		}
	}
	return removed, nil
}
