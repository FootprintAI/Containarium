package server

import (
	"crypto/rand"
	"errors"
	"fmt"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"strings"
)

const (
	// envGrafanaAdminPasswordFile overrides where the generated Grafana admin
	// password is kept on the host.
	envGrafanaAdminPasswordFile = "CONTAINARIUM_GRAFANA_ADMIN_PASSWORD_FILE" // #nosec G101 -- env var name, not a credential value

	// defaultGrafanaAdminPasswordFile sits next to the Postgres password file:
	// root-only, readable by the operator who administers the host.
	defaultGrafanaAdminPasswordFile = "/etc/containarium/grafana-admin.password" // #nosec G101 -- a file PATH, not a credential

	// grafanaAdminPasswordLen is long enough that guessing is not the threat,
	// and short enough to type if an operator has to.
	grafanaAdminPasswordLen = 32

	secretAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
)

// generateSecret returns n random alphanumeric characters from crypto/rand.
// The alphabet is deliberately limited: the value ends up in URLs, SQL and ini
// files, and none of those needs escaping for letters and digits.
func generateSecret(n int) (string, error) {
	if n <= 0 {
		return "", errors.New("secret length must be positive")
	}
	out := make([]byte, n)
	max := big.NewInt(int64(len(secretAlphabet)))
	for i := range out {
		idx, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", fmt.Errorf("read random bytes: %w", err)
		}
		out[i] = secretAlphabet[idx.Int64()]
	}
	return string(out), nil
}

// ensureGrafanaAdminPassword returns the Grafana admin password kept at path,
// creating it (random, mode 0600) when it does not exist. created reports
// whether this call made it.
//
// An existing file is only trusted if it passes the same permission check as
// the Postgres credential files, and an empty one is refused: a re-provision
// (the metrics container recreated) must keep the password the operator already
// saved, and must never turn an empty file into an empty password.
func ensureGrafanaAdminPassword(path string) (password string, created bool, err error) {
	if _, statErr := os.Stat(path); statErr == nil {
		b, err := readSecretFile(path, "Grafana admin password file")
		if err != nil {
			return "", false, err
		}
		pw := strings.TrimSpace(string(b))
		if pw == "" {
			return "", false, fmt.Errorf("%s is empty", path)
		}
		return pw, false, nil
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return "", false, statErr
	}

	pw, err := generateSecret(grafanaAdminPasswordLen)
	if err != nil {
		return "", false, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", false, err
	}
	// O_EXCL: never overwrite a file that appeared since the stat above.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- operator-configured path
	if err != nil {
		return "", false, err
	}
	if _, err := f.WriteString(pw + "\n"); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return "", false, err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(path)
		return "", false, err
	}
	return pw, true, nil
}

// grafanaAdminPasswordForProvisioning returns the admin password to put in a
// freshly provisioned grafana.ini, or "" when none can be kept safely.
//
// The template used to write a literal `admin_password = containarium`: a known
// login on a dashboard port every tenant on the bridge can reach (#2091). Now
// each host gets its own random password, saved where the operator can read it.
// If it cannot be saved, an unrecoverable random password would lock the
// operator out of the dashboards, so the key is omitted instead and Grafana
// forces a password change at first login; the warning says so.
func (cs *CoreServices) grafanaAdminPasswordForProvisioning() string {
	path := strings.TrimSpace(os.Getenv(envGrafanaAdminPasswordFile))
	if path == "" {
		path = defaultGrafanaAdminPasswordFile
	}
	pw, created, err := ensureGrafanaAdminPassword(path)
	if err != nil {
		log.Printf("WARNING: could not keep a generated Grafana admin password at %s: %v. "+
			"Grafana will use its own default admin login and prompts for a new password at first login; "+
			"change it immediately — the dashboard port is reachable from every tenant on the bridge.", path, err)
		return ""
	}
	if created {
		log.Printf("Generated the Grafana admin password for this host; saved to %s (mode 0600)", path)
	}
	return pw
}
