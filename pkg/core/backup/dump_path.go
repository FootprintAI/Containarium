package backup

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// stagingDumpPath returns a fresh path under /tmp inside the tenant container
// for one dump. kind names the operation (backup, restore, verify). The random
// suffix is what stops a tenant from guessing the name and pre-placing a
// symlink there, which the root-run dump would then write through (#3680).
func stagingDumpPath(kind, id string) (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("random staging name: %w", err)
	}
	return "/tmp/containarium-" + kind + "-" + id + "-" + hex.EncodeToString(b[:]) + ".dump", nil
}
