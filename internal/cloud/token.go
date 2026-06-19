package cloud

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/footprintai/containarium/internal/auth"
)

// MintDriverToken reads the daemon's JWT signing secret from secretFile and
// mints an admin JWT valid for ttl. This is the BYOC driver token (#554/#557):
// signed by the host's own secret, replayed by the cloud to drive this daemon
// through the sentinel peer-proxy. The cloud-stored token is sealed at rest;
// MintDriverToken is called at enroll time and then periodically by the
// driverRefreshLoop so the cloud-stored credential never reaches the 30-day cap.
func MintDriverToken(secretFile string, ttl time.Duration) (string, error) {
	secretFile = strings.TrimSpace(secretFile)
	if secretFile == "" {
		return "", fmt.Errorf("no jwt-secret-file")
	}
	secretBytes, err := os.ReadFile(secretFile) // #nosec G304 -- operator-provided daemon secret path
	if err != nil {
		return "", fmt.Errorf("read jwt secret %s: %w", secretFile, err)
	}
	secret := strings.TrimSpace(string(secretBytes))
	if secret == "" {
		return "", fmt.Errorf("jwt secret %s is empty", secretFile)
	}
	tm, err := auth.NewTokenManager(secret, "containarium")
	if err != nil {
		return "", fmt.Errorf("token manager: %w", err)
	}
	tok, err := tm.GenerateToken("cloud-byoc-driver", []string{"admin"}, ttl)
	if err != nil {
		return "", fmt.Errorf("mint driver token: %w", err)
	}
	return tok, nil
}
