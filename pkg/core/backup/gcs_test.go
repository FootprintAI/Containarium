package backup

import (
	"errors"
	"testing"
)

// A missing object on `gcloud storage rm` maps to ErrObjectNotFound so
// Delete can tell "nothing to delete" (the sidecar of a record written
// before #2402 uploaded sidecars) apart from a real failure, which keeps
// its gcloud output and is reported.
func TestGcloudUploader_DeleteMapsNotFound(t *testing.T) {
	for _, tc := range []struct {
		name     string
		out      string
		fail     bool
		notFound bool
	}{
		{"gcloud storage phrasing", "ERROR: (gcloud.storage.rm) The following URLs matched no objects or files:\ngs://b/x.meta.json", true, true},
		{"gsutil phrasing", "CommandException: No URLs matched: gs://b/x.meta.json", true, true},
		{"api not found", "ERROR: HTTPError 404: NotFound", true, true},
		{"permission denied is a real failure", "ERROR: (gcloud.storage.rm) HTTPError 403: user does not have storage.objects.delete access", true, false},
		{"success", "Removing gs://b/x.meta.json...", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := &GcloudUploader{run: func(args ...string) (string, error) {
				if tc.fail {
					return tc.out, errExec
				}
				return tc.out, nil
			}}
			err := g.Delete("gs://b/x.meta.json")
			switch {
			case !tc.fail && err != nil:
				t.Fatalf("Delete = %v, want nil", err)
			case tc.fail && err == nil:
				t.Fatal("Delete = nil, want an error")
			case tc.fail && errors.Is(err, ErrObjectNotFound) != tc.notFound:
				t.Errorf("Delete = %v; errors.Is(ErrObjectNotFound) = %v, want %v", err, !tc.notFound, tc.notFound)
			}
		})
	}
}
