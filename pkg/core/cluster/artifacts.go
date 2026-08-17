package cluster

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

// Pinned artifacts. THIS FILE IS THE REVIEWABLE SURFACE: what a release
// ships into tenant clusters is exactly what is pinned here, golden-
// tested so a bump is a visible one-line diff (same rule as the
// metrics-export allowlist). Checksums are the upstream-published
// sha256sum-amd64.txt values for the release.
//
// Artifacts are fetched onto the HOST cache and pushed into VMs over
// the Incus API — a cluster VM never downloads anything at bootstrap.
// The airgap image preload is a later cold-start optimization (design:
// "What has to change at 10x").
const (
	// K3sVersion is the k3s release every managed cluster runs.
	K3sVersion = "v1.33.4+k3s1"
	// K3sSHA256 is the sha256 of the linux-amd64 `k3s` binary.
	K3sSHA256 = "10da34c350ab8a02e4513a6021046db9e9afecc31bae77419bc6444cbd7b1400"
)

// DefaultArtifactBase is the host-side artifact cache root.
const DefaultArtifactBase = "/var/lib/containarium/artifacts"

func k3sDownloadURL() string {
	return "https://github.com/k3s-io/k3s/releases/download/" + url.PathEscape(K3sVersion) + "/k3s"
}

// K3sPath is where EnsureK3s caches the verified binary.
func K3sPath(base string) string {
	return filepath.Join(base, "k8s", K3sVersion, "k3s")
}

// EnsureK3s returns the path to the pinned, checksum-verified k3s
// binary in the host cache, downloading it first if absent. The
// checksum is verified on EVERY call — a corrupted or tampered cache
// entry fails closed rather than being pushed into a tenant's cluster.
func EnsureK3s(ctx context.Context, base string) (string, error) {
	path := K3sPath(base)
	if err := verifySHA256(path, K3sSHA256); err == nil {
		return path, nil
	}
	if err := fetchVerified(ctx, k3sDownloadURL(), path, K3sSHA256); err != nil {
		return "", fmt.Errorf("fetch k3s %s: %w", K3sVersion, err)
	}
	return path, nil
}

// fetchVerified downloads url into path atomically (tmp file + rename),
// accepting the result only if its sha256 matches want.
func fetchVerified(ctx context.Context, srcURL, path, want string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, srcURL, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: status %d", srcURL, resp.StatusCode)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".fetch-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := io.Copy(tmp, resp.Body); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o755); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := verifySHA256(tmp.Name(), want); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// verifySHA256 errors unless path exists and hashes to want.
func verifySHA256(path, want string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != want {
		return fmt.Errorf("sha256 mismatch for %s: got %s, want %s", path, got, want)
	}
	return nil
}
