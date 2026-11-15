package sdlcskills

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// LoadSignedBundle verifies one skills release and parses its bundle, in the
// order that keeps unverified bytes away from a parser: the signature over
// the manifest, then the manifest (and its contract), then the bundle's
// digest against the manifest's, and only then the archive.
func LoadSignedBundle(bundle, manifest, sig []byte, keys Keyring) (*Bundle, Manifest, error) {
	if err := keys.Verify(manifest, sig); err != nil {
		return nil, Manifest{}, fmt.Errorf("skills manifest signature: %w", err)
	}
	m, err := ParseManifest(manifest)
	if err != nil {
		return nil, Manifest{}, err
	}
	sum := sha256.Sum256(bundle)
	if got := hex.EncodeToString(sum[:]); got != m.SHA256 {
		return nil, Manifest{}, fmt.Errorf("sdlcskills: bundle digest %s does not match the signed manifest's digest %s", got[:12], m.SHA256[:12])
	}
	files, err := readBundleFiles(bundle)
	if err != nil {
		return nil, Manifest{}, err
	}
	// The pin keeps the shape a lock-verified bundle has (<repo>@<sha12>):
	// it is published as a hosted skill's prompt pin. The release version is
	// in the returned manifest.
	return &Bundle{pin: m.Pin(), files: files}, m, nil
}

// LoadSignedBundleFile reads the bundle at filePath with the manifest and
// signature beside it (ManifestName, SignatureName in the same directory) and
// verifies them with keys.
func LoadSignedBundleFile(filePath string, keys Keyring) (*Bundle, Manifest, error) {
	dir := filepath.Dir(filePath)
	bundle, err := readCapped(filePath, maxBundleBytes)
	if err != nil {
		return nil, Manifest{}, fmt.Errorf("sdlcskills: bundle: %w", err)
	}
	manifest, err := readCapped(filepath.Join(dir, ManifestName), maxManifestBytes)
	if err != nil {
		return nil, Manifest{}, fmt.Errorf("sdlcskills: manifest: %w", err)
	}
	sig, err := readCapped(filepath.Join(dir, SignatureName), maxManifestBytes)
	if err != nil {
		return nil, Manifest{}, fmt.Errorf("sdlcskills: signature: %w", err)
	}
	return LoadSignedBundle(bundle, manifest, sig, keys)
}

// readCapped reads at most limit bytes of the file at p; a larger file is an
// error rather than a truncated read.
func readCapped(p string, limit int) ([]byte, error) {
	f, err := os.Open(p) // #nosec G304 -- operator-configured path; the content is verified by signature before use
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(data) > limit {
		return nil, fmt.Errorf("%s exceeds %d bytes", p, limit)
	}
	return data, nil
}
