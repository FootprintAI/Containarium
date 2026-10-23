package audit

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// #2912 "should fix" items from the post-merge review of #2882.

// gcloud expands * ? [ in a gs:// URL, so a wildcard prefix would make
// LastPublished list something else and silently report "never anchored".
func TestNewGCSAnchorSink_RejectsWildcardsAndOddNames(t *testing.T) {
	g := newFakeGcloud()
	for _, uri := range []string{
		"gs://example-bucket/audit-*",
		"gs://example-bucket/a?b",
		"gs://example-bucket/a[0-9]",
		"gs://example-*",
		"gs://Example_Bucket",
		"gs://example-bucket/a/../b",
		"gs://example-bucket/a//b",
	} {
		if _, err := newGCSAnchorSink(uri, g.run); err == nil {
			t.Errorf("newGCSAnchorSink(%q) = nil error, want it rejected", uri)
		}
	}
	for _, uri := range []string{
		"gs://example-bucket/audit-anchors",
		"gs://example.bucket-1/a/b_c.d",
	} {
		if _, err := newGCSAnchorSink(uri, g.run); err != nil {
			t.Errorf("newGCSAnchorSink(%q): %v, want accepted", uri, err)
		}
	}
}

// A bucket-level failure from `ls` is an error, never "never anchored".
func TestGCSAnchorSink_BucketLevelListFailureIsAnError(t *testing.T) {
	for _, msg := range []string{
		"exit status 1: ERROR: HTTPError 404: The specified bucket does not exist.",
		"exit status 1: ERROR: HTTPError 403: caller does not have storage.objects.list access",
		"exit status 1: ERROR: gs://example-bucket/audit-anchors/ 404",
	} {
		s, err := newGCSAnchorSink("gs://example-bucket/audit-anchors", func(context.Context, []byte, ...string) (string, error) {
			return "", errors.New(msg)
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, _, ok, err := s.LastPublished(context.Background()); err == nil || ok {
			t.Errorf("%q: LastPublished = (ok=%v, err=%v), want an error", msg, ok, err)
		}
	}
}

// An object whose body names a different checkpoint than its object name is
// rejected, not trusted.
func TestGCSAnchorSink_ObjectNameMustMatchItsCheckpoint(t *testing.T) {
	g := newFakeGcloud()
	s := newTestGCSSink(t, g)
	g.objects[s.objectURI(5)] = []byte(`{"checkpoint":9,"root":"r","anchored_at":"2026-01-01T00:00:00Z"}` + "\n")
	_, _, _, err := s.LastPublished(context.Background())
	if err == nil || !strings.Contains(err.Error(), "belongs at") {
		t.Fatalf("LastPublished err = %v, want a name/checkpoint mismatch error", err)
	}
}

// "412" inside an object name is not a precondition failure.
func TestIsGcloudPreconditionFailed(t *testing.T) {
	tests := []struct {
		msg  string
		want bool
	}{
		{"exit status 1: ERROR: HTTPError 412: At least one of the pre-conditions you specified did not hold.", true},
		{"exit status 1: ERROR: Precondition Failed", true},
		{"exit status 1: ERROR: network down while writing gs://example-bucket/audit-anchors/00000000000000000412.json", false},
		{"exit status 1: ERROR: gs://example-bucket/412/x: connection reset", false},
	}
	for _, tc := range tests {
		if got := isGcloudPreconditionFailed(errors.New(tc.msg)); got != tc.want {
			t.Errorf("isGcloudPreconditionFailed(%q) = %v, want %v", tc.msg, got, tc.want)
		}
	}
}
