// Package cloud is the OSS daemon's cloud-actuation client (#354 /
// docs/CLOUD-ACTUATION-CLIENT-DESIGN.md): the opt-in mode where a registered
// host receives desired-state container assignments + per-org network policies
// from a cloud control plane and reconciles them locally.
//
// This file is the local enrollment config — the host-bearer token + control
// plane address an operator writes once via `containarium cloud login`. It is
// deliberately dependency-free (no cloud proto, no gRPC) so it builds in the
// default OSS binary; the actuation client itself (heartbeat / WatchAssignments)
// lands in later slices and consumes this.
package cloud

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// DefaultRelPath is the cloud-enrollment config location under $HOME, alongside
// the user-JWT credentials.json. Kept separate: credentials.json is the
// user-facing JWT (`containarium login`); this is the host-bearer the daemon
// uses for the actuation channel (`containarium cloud login`).
const DefaultRelPath = ".containarium/cloud.yaml"

// Config is a host's cloud-actuation enrollment. Written by `containarium cloud
// login`; read by the daemon on startup to decide whether to run the actuation
// client.
type Config struct {
	// ControlPlane is the cloud-daemon's gRPC address (host:port).
	ControlPlane string `yaml:"control_plane"`
	// HostID is the cloud-assigned host UUID (from the sysadmin who ran CreateHost).
	HostID string `yaml:"host_id"`
	// Token is the opaque, single-host-scoped host bearer. Sent as the
	// host-bearer gRPC metadata on every actuation RPC; never parsed here.
	Token string `yaml:"token"`
	// Insecure dials the control plane without TLS. Default false (TLS). Only
	// for a self-hosted plaintext control plane or local dev — never for a
	// public cloud endpoint.
	Insecure bool `yaml:"insecure,omitempty"`
	// JWTSecretFile is the path to this daemon's JWT signing secret (#557).
	// When set, the daemon's cloud actuation client re-mints a fresh driver
	// token every ~⅔ of the 30-day cap and pushes it to the cloud via
	// ReportHostStatus so the cloud-stored credential never expires.
	// Written by `containarium cloud enroll`.
	//
	// EMPTY no longer disables auto-refresh (cloud#888/#903 postmortem): a
	// cloud.yaml written by a pre-#557 enroll has no jwt_secret_file, and
	// nothing backfills the config on daemon upgrades — so legacy-enrolled
	// hosts silently never rotated and their cloud-stored driver token died
	// at the 30-day cap. When empty, the daemon falls back to the default
	// secret path if it's readable; set DriverTokenDisabled to genuinely
	// opt out.
	JWTSecretFile string `yaml:"jwt_secret_file,omitempty"`
	// DriverTokenDisabled explicitly opts this host out of driver-token
	// auto-refresh (the durable form of `--no-driver-token`): the cloud
	// can't place workloads on the host, and the daemon must not push
	// tokens that would silently re-enable drivability. Distinct from an
	// EMPTY JWTSecretFile, which legacy enrollments produced without any
	// intent to opt out.
	DriverTokenDisabled bool `yaml:"driver_token_disabled,omitempty"`
}

// DefaultDaemonJWTSecretFile is where the daemon's JWT signing secret lives on
// a standard install — the daemon-side fallback when cloud.yaml predates
// jwt_secret_file (see JWTSecretFile), and the enroll CLI's flag default.
const DefaultDaemonJWTSecretFile = "/etc/containarium/jwt.secret" // #nosec G101 -- a file PATH, not a credential

// ResolveDriverSecretFile decides which JWT-secret path (if any) the daemon
// should mint driver-token refreshes from (cloud#888/#903 postmortem):
//
//   - DriverTokenDisabled → "" (explicit opt-out, the durable
//     `--no-driver-token`).
//   - JWTSecretFile set → that path (the post-#557 enroll wrote it).
//   - JWTSecretFile empty → DefaultDaemonJWTSecretFile IF it exists — a
//     legacy (pre-#557) cloud.yaml simply predates the field; treating
//     empty as "disabled" is what let legacy hosts' cloud-stored driver
//     tokens silently expire at the 30-day cap.
//   - Otherwise "" (nothing to mint from; caller warns loudly).
//
// statFn abstracts os.Stat for tests; pass nil for the real filesystem.
func ResolveDriverSecretFile(cfg *Config, statFn func(string) error) string {
	if cfg == nil || cfg.DriverTokenDisabled {
		return ""
	}
	if cfg.JWTSecretFile != "" {
		return cfg.JWTSecretFile
	}
	if statFn == nil {
		statFn = func(p string) error {
			_, err := os.Stat(p)
			return err
		}
	}
	if statFn(DefaultDaemonJWTSecretFile) == nil {
		return DefaultDaemonJWTSecretFile
	}
	return ""
}

// DefaultPath resolves $HOME/.containarium/cloud.yaml.
func DefaultPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home directory: %w", err)
	}
	return filepath.Join(home, DefaultRelPath), nil
}

// Load reads the config at path. A missing file is not an error — it returns
// (nil, nil), meaning "not enrolled" (the daemon then runs single-tenant).
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path) // #nosec G304 -- path is operator-provided config location
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read cloud config: %w", err)
	}
	if len(b) == 0 {
		return nil, nil
	}
	var c Config
	if err := yaml.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("parse cloud config %s: %w", path, err)
	}
	return &c, nil
}

// Validate reports whether the config has the fields the client needs.
func (c *Config) Validate() error {
	if c == nil {
		return fmt.Errorf("nil cloud config")
	}
	var missing []string
	if strings.TrimSpace(c.ControlPlane) == "" {
		missing = append(missing, "control_plane")
	}
	if strings.TrimSpace(c.HostID) == "" {
		missing = append(missing, "host_id")
	}
	if strings.TrimSpace(c.Token) == "" {
		missing = append(missing, "token")
	}
	if len(missing) > 0 {
		return fmt.Errorf("cloud config missing: %s", strings.Join(missing, ", "))
	}
	return nil
}

// Save writes the config to path atomically at mode 0600 (it holds a bearer
// token). Creates the parent dir at 0700.
func Save(path string, c *Config) error {
	if c == nil {
		return fmt.Errorf("nil cloud config")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create cloud config dir %s: %w", dir, err)
	}
	b, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("marshal cloud config: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".cloud-*.yaml.tmp")
	if err != nil {
		return fmt.Errorf("create temp cloud config: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }() // no-op if the rename succeeded
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod temp cloud config: %w", err)
	}
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp cloud config: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp cloud config: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("rename cloud config into place: %w", err)
	}
	return nil
}

// Delete removes the config (logout). Missing file is not an error.
func Delete(path string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove cloud config: %w", err)
	}
	return nil
}
