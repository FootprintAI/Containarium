package backup

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
)

// GcloudUploader implements Uploader by shelling out to the host's
// `gcloud storage` CLI. This mirrors how the rest of Containarium drives
// host tooling (incus, podman, gcloud for the secrets master-key backup
// in docs/SECRETS-OPERATIONS.md) rather than pulling in a cloud SDK and
// its credential-discovery surface. Authentication is whatever the host's
// gcloud is configured with (service account on a GCE VM, ADC, etc.).
type GcloudUploader struct {
	bin string
	// run executes `gcloud <args...>` and returns combined output. A field
	// so tests can substitute a fake without invoking the real binary.
	run func(args ...string) (string, error)
}

// DownloadStream copies object bytes to a caller-controlled, bounded writer.
// gcloud's stdout is never captured in memory or written outside that bound.
func (g *GcloudUploader) DownloadStream(destURI string, dst io.Writer) error {
	if err := validateGSURI(destURI); err != nil {
		return err
	}
	// #nosec G204 -- fixed storage verb, validated URI, executable resolved by LookPath
	cmd := exec.Command(g.bin, "storage", "cat", destURI)
	cmd.Stdout = dst
	diagnostic := &downloadDiagnostic{}
	cmd.Stderr = diagnostic
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("gcloud storage cat: %w: %s", err, strings.TrimSpace(diagnostic.String()))
	}
	return nil
}

// Keep diagnostics bounded too, while continuing to drain stderr.
type downloadDiagnostic struct{ bytes.Buffer }

func (d *downloadDiagnostic) Write(p []byte) (int, error) {
	n := len(p)
	if remaining := 4096 - d.Len(); remaining > 0 {
		if len(p) > remaining {
			p = p[:remaining]
		}
		_, _ = d.Buffer.Write(p)
	}
	return n, nil
}

// NewGcloudUploader locates `gcloud` on PATH. Returns an error if it is
// not installed, so the daemon can fall back to local-only backups with a
// clear log line rather than failing every GCS request opaquely.
func NewGcloudUploader() (*GcloudUploader, error) {
	bin, err := exec.LookPath("gcloud")
	if err != nil {
		return nil, fmt.Errorf("gcloud not found on PATH (required for GCS backups): %w", err)
	}
	u := &GcloudUploader{bin: bin}
	u.run = func(args ...string) (string, error) {
		// #nosec G204 -- u.bin is resolved via exec.LookPath("gcloud"); callers
		// pass fixed verbs ("storage", "cp", ...) plus gs:// URIs validated by
		// validateGSURI and host-internal paths. No shell is involved.
		out, err := exec.Command(u.bin, args...).CombinedOutput()
		return string(out), err
	}
	return u, nil
}

func (g *GcloudUploader) Upload(localPath, destURI string) error {
	if err := validateGSURI(destURI); err != nil {
		return err
	}
	if out, err := g.run("storage", "cp", localPath, destURI); err != nil {
		return fmt.Errorf("gcloud storage cp: %w: %s", err, strings.TrimSpace(out))
	}
	return nil
}

func (g *GcloudUploader) Download(destURI, localPath string) error {
	if err := validateGSURI(destURI); err != nil {
		return err
	}
	if out, err := g.run("storage", "cp", destURI, localPath); err != nil {
		return fmt.Errorf("gcloud storage cp: %w: %s", err, strings.TrimSpace(out))
	}
	return nil
}

// ErrObjectNotFound is returned by Uploader.Delete when the object was
// not there to begin with. Delete callers treat it as "nothing to do" for
// the sidecar object of a record written before sidecars were uploaded
// (#2402); every other delete failure is a real one.
var ErrObjectNotFound = errors.New("object not found")

func (g *GcloudUploader) Delete(destURI string) error {
	if err := validateGSURI(destURI); err != nil {
		return err
	}
	if out, err := g.run("storage", "rm", destURI); err != nil {
		if isGcloudNotFound(out) {
			return fmt.Errorf("gcloud storage rm %s: %w", destURI, ErrObjectNotFound)
		}
		return fmt.Errorf("gcloud storage rm: %w: %s", err, strings.TrimSpace(out))
	}
	return nil
}

// isGcloudNotFound recognises `gcloud storage rm` (and legacy gsutil)
// complaining that the URL matched nothing, as opposed to a permission,
// network or bucket error.
func isGcloudNotFound(out string) bool {
	s := strings.ToLower(out)
	return strings.Contains(s, "matched no objects") ||
		strings.Contains(s, "no urls matched") ||
		strings.Contains(s, "notfound") ||
		strings.Contains(s, "not found")
}

func validateGSURI(uri string) error {
	if !strings.HasPrefix(uri, "gs://") {
		return fmt.Errorf("expected a gs:// URI, got %q", uri)
	}
	return nil
}
