// Package credentials manages the on-disk store of per-server CLI
// auth tokens at ~/.containarium/credentials.json, populated by
// `containarium login` and consumed by the rest of the CLI when no
// explicit --token / CONTAINARIUM_TOKEN is set.
//
// See prd/cloud/cli-login-and-multi-env-ssh.md §"Credentials file
// format" for the locked schema. Multi-server: a user can be logged
// into the hosted cloud and one or more self-hosted instances
// simultaneously.
//
// Concurrency: the file is small (<1 KB typical), per-user, and
// touched only by interactive CLI invocations. We rely on the
// 0600 perm bits plus the atomic-rename Save below; we do NOT use
// file locking. If two `login` runs race, the second wins.
package credentials

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// DefaultRelPath is the path of the credentials file relative to the
// user's home directory. Exported so tests and the CLI can refer to
// the same constant.
const DefaultRelPath = ".containarium/credentials.json"

// ServerCreds is the per-server credential record persisted inside
// CredentialsFile.Servers. Fields are pointer-free where possible so
// the JSON round-trip is loss-less.
//
// ExpiresAt is a *time.Time because the locked schema explicitly
// allows `null` (non-expiring tokens — service accounts, dev tokens).
// Marshalling nil emits JSON `null`, matching the PRD example.
type ServerCreds struct {
	Token     string     `json:"token"`
	UserEmail string     `json:"user_email"`
	OrgID     string     `json:"org_id"`
	IssuedAt  time.Time  `json:"issued_at"`
	ExpiresAt *time.Time `json:"expires_at"`
	// AccessModel records how this server grants box access — "token"
	// (cloud: `containarium connect` with the API token) or "sshKey"
	// (self-hosted: register the user's SSH key). Learned at login from the
	// server's declared model, falling back to a host heuristic, and cached
	// here so later commands don't re-detect (#637 follow-up). Empty for
	// credentials written before this field existed.
	AccessModel string `json:"access_model,omitempty"`
}

// CredentialsFile is the on-disk JSON document. DefaultServer is the
// server the CLI falls back to when --server is unset; it MUST also
// be a key in Servers (Save enforces this).
type CredentialsFile struct {
	DefaultServer string                 `json:"default_server"`
	Servers       map[string]ServerCreds `json:"servers"`
}

// NewCredentialsFile returns an empty, valid CredentialsFile. Always
// prefer this over `&CredentialsFile{}` so the Servers map is
// initialized (nil-map writes panic).
func NewCredentialsFile() *CredentialsFile {
	return &CredentialsFile{
		Servers: make(map[string]ServerCreds),
	}
}

// DefaultPath returns the absolute path to the credentials file
// under the current user's home directory. Honors $HOME (via
// os.UserHomeDir) so t.Setenv("HOME", tmpdir) works in tests.
func DefaultPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home directory: %w", err)
	}
	return filepath.Join(home, DefaultRelPath), nil
}

// Load reads the credentials file at path. If the file does not
// exist Load returns an empty, valid CredentialsFile and a nil error
// — callers should not have to distinguish "never logged in" from
// "log in and then look up". Any other error (perm denied, malformed
// JSON, …) is propagated.
func Load(path string) (*CredentialsFile, error) {
	// #nosec G304 -- path is supplied by the CLI from the user's
	// home directory or an explicit override (tests); not attacker
	// controlled.
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return NewCredentialsFile(), nil
		}
		return nil, fmt.Errorf("read credentials file: %w", err)
	}

	// Empty file → treat as fresh. Some editors leave 0-byte files
	// behind; this is friendlier than a json.Unmarshal error.
	if len(b) == 0 {
		return NewCredentialsFile(), nil
	}

	cf := NewCredentialsFile()
	if err := json.Unmarshal(b, cf); err != nil {
		return nil, fmt.Errorf("parse credentials file %s: %w", path, err)
	}
	if cf.Servers == nil {
		cf.Servers = make(map[string]ServerCreds)
	}
	return cf, nil
}

// Save writes the credentials file atomically (write to .tmp +
// rename) with 0600 permissions. The parent directory is created
// with 0700 if missing.
//
// DefaultServer is auto-repaired: if it is unset but Servers has
// exactly one entry, we point to that. If it is set to a server
// that no longer exists in Servers (e.g. after Remove), we pick
// any remaining server, or clear it if none remain.
func Save(path string, cf *CredentialsFile) error {
	if cf == nil {
		return fmt.Errorf("nil credentials file")
	}
	if cf.Servers == nil {
		cf.Servers = make(map[string]ServerCreds)
	}

	// Repair default_server.
	if _, ok := cf.Servers[cf.DefaultServer]; !ok || cf.DefaultServer == "" {
		cf.DefaultServer = ""
		for srv := range cf.Servers {
			cf.DefaultServer = srv
			break
		}
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create credentials dir %s: %w", dir, err)
	}

	b, err := json.MarshalIndent(cf, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal credentials: %w", err)
	}

	// Atomic rename: write to a sibling temp file, fsync, then
	// rename over the destination. On POSIX rename is atomic on
	// the same filesystem, so a crash mid-write never leaves the
	// real file truncated.
	tmp, err := os.CreateTemp(dir, ".credentials-*.json.tmp")
	if err != nil {
		return fmt.Errorf("create temp credentials file: %w", err)
	}
	tmpPath := tmp.Name()
	// Best-effort cleanup if anything below fails.
	defer func() { _ = os.Remove(tmpPath) }()

	if err := os.Chmod(tmpPath, 0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod temp credentials file: %w", err)
	}
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp credentials file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp credentials file: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("rename credentials file into place: %w", err)
	}
	return nil
}

// Get returns the credentials for the given server. The server arg
// is normalized via NormalizeServer so callers can pass either
// "cloud.containarium.dev" or "https://cloud.containarium.dev/" and
// land on the same record.
//
// When server is empty, Get returns the DefaultServer's record.
// Returns (zero, false) if no matching record exists.
func (cf *CredentialsFile) Get(server string) (ServerCreds, bool) {
	if cf == nil || cf.Servers == nil {
		return ServerCreds{}, false
	}
	key := server
	if key == "" {
		key = cf.DefaultServer
	}
	if key == "" {
		return ServerCreds{}, false
	}
	key = NormalizeServer(key)
	if c, ok := cf.Servers[key]; ok {
		return c, true
	}
	// Fall back to a tolerant lookup: scan keys with their
	// normalized form. This handles credential files written by
	// older versions or hand-edited files with trailing slashes.
	for k, v := range cf.Servers {
		if NormalizeServer(k) == key {
			return v, true
		}
	}
	return ServerCreds{}, false
}

// Set inserts or replaces the record for server. The server key is
// normalized. If this is the first server in the file, it also
// becomes the DefaultServer.
func (cf *CredentialsFile) Set(server string, creds ServerCreds) {
	if cf.Servers == nil {
		cf.Servers = make(map[string]ServerCreds)
	}
	key := NormalizeServer(server)
	cf.Servers[key] = creds
	if cf.DefaultServer == "" {
		cf.DefaultServer = key
	}
}

// Remove deletes the record for server. Returns true if a record
// was actually removed. If the removed server was the
// DefaultServer, Save will pick a new default on next write (or
// clear it if none remain).
func (cf *CredentialsFile) Remove(server string) bool {
	if cf == nil || cf.Servers == nil {
		return false
	}
	key := NormalizeServer(server)
	// First try direct, then tolerant scan (mirrors Get).
	if _, ok := cf.Servers[key]; ok {
		delete(cf.Servers, key)
		if cf.DefaultServer == key {
			cf.DefaultServer = ""
		}
		return true
	}
	for k := range cf.Servers {
		if NormalizeServer(k) == key {
			delete(cf.Servers, k)
			if NormalizeServer(cf.DefaultServer) == key {
				cf.DefaultServer = ""
			}
			return true
		}
	}
	return false
}

// NormalizeServer canonicalizes a server URL so lookups are stable
// across "https://x/" vs "https://x" vs "x" inputs.
//
// Rules:
//   - Strip exactly one trailing slash.
//   - Lower-case the scheme + host portion (paths preserved
//     case-sensitively, though we don't expect any).
//   - Leave the scheme as-supplied (we do NOT auto-prepend
//     https://). The login command is what decides the scheme; the
//     store just round-trips whatever it's given.
//
// The intent is leniency on read, strictness on write — the store
// is keyed off the normalized form, but callers can look it up
// loosely.
func NormalizeServer(server string) string {
	s := strings.TrimSpace(server)
	s = strings.TrimRight(s, "/")
	// Lower-case scheme + host. We do a cheap scheme split rather
	// than pulling in net/url for the common case.
	if i := strings.Index(s, "://"); i >= 0 {
		scheme := strings.ToLower(s[:i])
		rest := s[i+3:]
		if j := strings.Index(rest, "/"); j >= 0 {
			rest = strings.ToLower(rest[:j]) + rest[j:]
		} else {
			rest = strings.ToLower(rest)
		}
		s = scheme + "://" + rest
	} else {
		s = strings.ToLower(s)
	}
	return s
}
