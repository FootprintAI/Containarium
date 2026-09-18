package releases

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestFetchSHA256_FindsNamedBinary pins the GNU sha256sum-style parsing
// (SHA256SUMS.txt lines are "<hash>  <filename>") against a fixture that
// carries several binaries, only one of which is asked for.
func TestFetchSHA256_FindsNamedBinary(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/SHA256SUMS.txt") {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		_, _ = w.Write([]byte(
			"aaaa1111  containarium-linux-amd64\n" +
				"bbbb2222  containariumd-linux-amd64\n" +
				"cccc3333  containarium-windows-amd64.exe\n"))
	}))
	defer srv.Close()

	orig := GitHubReleaseBaseURL
	GitHubReleaseBaseURL = srv.URL
	t.Cleanup(func() { GitHubReleaseBaseURL = orig })

	got, err := FetchSHA256(context.Background(), "v0.55.0", "containariumd-linux-amd64")
	if err != nil {
		t.Fatalf("FetchSHA256: %v", err)
	}
	if got != "bbbb2222" {
		t.Errorf("checksum = %q, want bbbb2222", got)
	}
}

// TestFetchSHA256_UnknownBinaryIsError proves a name absent from the sums
// file is a clear error, not a silently-empty/wrong checksum.
func TestFetchSHA256_UnknownBinaryIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("aaaa1111  containarium-linux-amd64\n"))
	}))
	defer srv.Close()

	orig := GitHubReleaseBaseURL
	GitHubReleaseBaseURL = srv.URL
	t.Cleanup(func() { GitHubReleaseBaseURL = orig })

	if _, err := FetchSHA256(context.Background(), "v0.55.0", "does-not-exist"); err == nil {
		t.Fatal("expected an error for a binary name absent from SHA256SUMS.txt")
	}
}

// TestFetchSHA256_NonOKStatusIsError proves a 404 (e.g. a bad/unpublished
// tag) surfaces as an error rather than an empty checksum match.
func TestFetchSHA256_NonOKStatusIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	orig := GitHubReleaseBaseURL
	GitHubReleaseBaseURL = srv.URL
	t.Cleanup(func() { GitHubReleaseBaseURL = orig })

	if _, err := FetchSHA256(context.Background(), "v9.9.9-nope", "containariumd-linux-amd64"); err == nil {
		t.Fatal("expected an error for a 404 SHA256SUMS.txt")
	}
}

func TestBinaryDownloadURL(t *testing.T) {
	orig := GitHubReleaseBaseURL
	GitHubReleaseBaseURL = "https://github.com/FootprintAI/Containarium/releases/download"
	t.Cleanup(func() { GitHubReleaseBaseURL = orig })

	got := BinaryDownloadURL("v0.55.0", "containariumd-linux-amd64")
	want := "https://github.com/FootprintAI/Containarium/releases/download/v0.55.0/containariumd-linux-amd64"
	if got != want {
		t.Errorf("BinaryDownloadURL = %q, want %q", got, want)
	}
}
