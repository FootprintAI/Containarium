package sentinel

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// servedVersionResponse is the /containarium/version body: the version of the
// binary this sentinel serves at /containarium, plus the checksum it was read
// from so a caller can tie the two together. #2171.
type servedVersionResponse struct {
	Version  string `json:"version"`
	Checksum string `json:"checksum"`
}

// servedVersionCache reports the served binary's own version. It is read from
// the FILE (by running its `version` subcommand), not from this process's
// build info: /sentinel/version reports the running sentinel, which only
// matches the served binary until someone swaps the file without a restart.
// The probe execs a binary, so the result is cached per checksum and probes
// are serialized.
type servedVersionCache struct {
	probe func(ctx context.Context, binaryPath string) (string, error)

	mu       sync.Mutex
	checksum string
	version  string
}

func newServedVersionCache() *servedVersionCache {
	return &servedVersionCache{probe: probeBinaryVersion}
}

func (c *servedVersionCache) get(ctx context.Context, binaryPath string) (servedVersionResponse, error) {
	sum, err := sha256File(binaryPath)
	if err != nil {
		return servedVersionResponse{}, fmt.Errorf("checksum served binary: %w", err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if sum != c.checksum {
		v, err := c.probe(ctx, binaryPath)
		if err != nil {
			return servedVersionResponse{}, err
		}
		c.checksum, c.version = sum, v
	}
	return servedVersionResponse{Version: c.version, Checksum: c.checksum}, nil
}

func (c *servedVersionCache) handler(binaryPath string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		out, err := c.get(r.Context(), binaryPath)
		if err != nil {
			log.Printf("[sentinel] /containarium/version: %v", err)
			http.Error(w, "version unavailable", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	}
}

// probeBinaryVersion runs `<binaryPath> version` and parses its output. The
// same binary is already smoke-tested this way by fetch-release before it is
// installed, so executing it here adds no new trust.
func probeBinaryVersion(ctx context.Context, binaryPath string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, binaryPath, "version").Output() // #nosec G204 -- binaryPath is the sentinel's own trusted served-binary path
	if err != nil {
		return "", fmt.Errorf("run %s version: %w", binaryPath, err)
	}
	return parseVersionOutput(string(out))
}

// parseVersionOutput extracts the version from `containarium version` output
// ("Containarium v0.91.1"), without the leading "v" to match
// pkg/version.Version and the daemon's current_version.
func parseVersionOutput(out string) (string, error) {
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if rest, ok := strings.CutPrefix(line, "Containarium "); ok {
			if v := strings.TrimPrefix(strings.TrimSpace(rest), "v"); v != "" {
				return v, nil
			}
		}
	}
	return "", fmt.Errorf("no version line in output %q", strings.TrimSpace(out))
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path) // #nosec G304 -- path is the sentinel's trusted served-binary path
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
