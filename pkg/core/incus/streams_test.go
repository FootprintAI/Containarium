package incus

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Phase 3.1 Phase-A — simplestreams resolver tests.
//
// We stand up a httptest server that serves a canned
// images.json. The resolver fetches from it under the
// same path the production simplestreams remotes use, so
// the only difference between test and real is the
// hostname.

// fakeIndex builds a minimal-but-realistic simplestreams
// products:1.0 index with one product (`ubuntu/24.04`)
// having two versions, each with three items.
func fakeIndex() imagesIndex {
	return imagesIndex{
		Format: "products:1.0",
		Products: map[string]productEntry{
			"ubuntu:24.04:amd64:default": {
				Aliases: "24.04,noble,ubuntu/24.04",
				Arch:    "amd64",
				Versions: map[string]versionEntry{
					"20240519_07:42": {
						Items: map[string]itemEntry{
							"lxd.tar.xz": {
								FType:  "lxd.tar.xz",
								SHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
								Size:   12345,
							},
							"root.squashfs": {
								FType:  "squashfs",
								SHA256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
								Size:   67890,
							},
							"lxd_combined.tar.gz": {
								FType:  "lxd_combined.tar.gz",
								SHA256: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
								Size:   98765,
							},
						},
					},
					"20240520_07:42": {
						Items: map[string]itemEntry{
							"lxd.tar.xz": {
								FType:  "lxd.tar.xz",
								SHA256: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
								Size:   12345,
							},
						},
					},
				},
			},
			"alpine:3.19:amd64:default": {
				Aliases: "3.19,alpine/3.19",
				Arch:    "amd64",
				Versions: map[string]versionEntry{
					"20240301_13:00": {
						Items: map[string]itemEntry{
							"root.squashfs": {
								FType:  "squashfs",
								SHA256: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
								Size:   45678,
							},
						},
					},
				},
			},
		},
	}
}

// newFakeStreamsServer serves the fakeIndex JSON at the
// canonical simplestreams path. Returns the test server
// and a *bool the test can flip to make the next request
// 500.
func newFakeStreamsServer(t *testing.T) (*httptest.Server, *bool) {
	t.Helper()
	fail := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != indexPath {
			http.NotFound(w, r)
			return
		}
		if fail {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(fakeIndex())
	}))
	return srv, &fail
}

// --- Tests ---

func TestResolveImageDigests_HappyPath(t *testing.T) {
	srv, _ := newFakeStreamsServer(t)
	defer srv.Close()

	r := NewStreamsResolver(0)
	got, err := r.ResolveImageDigests(context.Background(), srv.URL, "ubuntu/24.04")
	if err != nil {
		t.Fatalf("ResolveImageDigests: %v", err)
	}
	// Expect all 4 distinct digests across both versions
	// of the ubuntu product. Order is non-deterministic
	// because we walk a map; assert on set membership.
	if len(got) != 4 {
		t.Fatalf("got %d digests, want 4: %v", len(got), got)
	}
	want := []string{
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
	}
	for _, w := range want {
		if !contains(got, w) {
			t.Errorf("missing digest %q in result %v", w, got)
		}
	}
}

func TestResolveImageDigests_AliasAlternates(t *testing.T) {
	// The product's alias list is "24.04,noble,ubuntu/24.04".
	// All three should resolve to the same digest set.
	srv, _ := newFakeStreamsServer(t)
	defer srv.Close()
	r := NewStreamsResolver(0)

	for _, alias := range []string{"24.04", "noble", "ubuntu/24.04", "UBUNTU/24.04", " 24.04 "} {
		got, err := r.ResolveImageDigests(context.Background(), srv.URL, alias)
		if err != nil {
			t.Fatalf("alias %q: %v", alias, err)
		}
		if len(got) != 4 {
			t.Errorf("alias %q: got %d digests, want 4", alias, len(got))
		}
	}
}

func TestResolveImageDigests_AliasNotFoundIsEmpty(t *testing.T) {
	// Unknown aliases return (nil, nil) — the caller
	// decides whether that's an error in their context.
	srv, _ := newFakeStreamsServer(t)
	defer srv.Close()
	r := NewStreamsResolver(0)

	got, err := r.ResolveImageDigests(context.Background(), srv.URL, "gentoo/rolling")
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("got %d digests, want 0: %v", len(got), got)
	}
}

func TestResolveImageDigests_SubstringAliasDoesNotMatch(t *testing.T) {
	// The product alias is "24.04" — a request for
	// "4.04" must NOT match. Substring matches are a
	// classic source of allowlist bypasses; we test the
	// negative.
	srv, _ := newFakeStreamsServer(t)
	defer srv.Close()
	r := NewStreamsResolver(0)

	got, err := r.ResolveImageDigests(context.Background(), srv.URL, "4.04")
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("substring match leaked through: %v", got)
	}
}

func TestResolveImageDigests_MultipleProducts(t *testing.T) {
	// Aliases from different products should resolve
	// independently — alpine doesn't bleed into ubuntu
	// and vice versa.
	srv, _ := newFakeStreamsServer(t)
	defer srv.Close()
	r := NewStreamsResolver(0)

	alpine, err := r.ResolveImageDigests(context.Background(), srv.URL, "alpine/3.19")
	if err != nil {
		t.Fatalf("alpine resolve: %v", err)
	}
	if len(alpine) != 1 {
		t.Fatalf("alpine got %d, want 1: %v", len(alpine), alpine)
	}
	if alpine[0] != "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" {
		t.Errorf("wrong alpine digest: %s", alpine[0])
	}
}

func TestResolveImageDigests_EmptyServerOrAlias(t *testing.T) {
	r := NewStreamsResolver(0)
	if _, err := r.ResolveImageDigests(context.Background(), "", "ubuntu/24.04"); err == nil {
		t.Error("empty server should error")
	}
	if _, err := r.ResolveImageDigests(context.Background(), "https://x", ""); err == nil {
		t.Error("empty alias should error")
	}
}

func TestResolveImageDigests_HTTP500PropagatesError(t *testing.T) {
	srv, fail := newFakeStreamsServer(t)
	defer srv.Close()
	*fail = true

	r := NewStreamsResolver(0)
	_, err := r.ResolveImageDigests(context.Background(), srv.URL, "ubuntu/24.04")
	if err == nil {
		t.Fatal("HTTP 500 should produce an error")
	}
	if !strings.Contains(err.Error(), "status 500") {
		t.Errorf("error should mention status; got %v", err)
	}
}

func TestResolveImageDigests_BadJSONErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("not json"))
	}))
	defer srv.Close()
	r := NewStreamsResolver(0)
	_, err := r.ResolveImageDigests(context.Background(), srv.URL, "ubuntu/24.04")
	if err == nil {
		t.Fatal("bad JSON should error")
	}
}

func TestResolveImageDigests_RejectsUnknownIndexFormat(t *testing.T) {
	// A future simplestreams v2 would change `format`.
	// Until the resolver is taught the new shape, we must
	// fail loudly rather than silently mis-parse.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"format":"products:2.0","products":{}}`))
	}))
	defer srv.Close()
	r := NewStreamsResolver(0)
	_, err := r.ResolveImageDigests(context.Background(), srv.URL, "ubuntu/24.04")
	if err == nil {
		t.Fatal("unknown index format should error")
	}
	if !strings.Contains(err.Error(), "unrecognized index format") {
		t.Errorf("error should call out the format; got %v", err)
	}
}

func TestResolveImageDigests_TimeoutHonored(t *testing.T) {
	hang := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second)
	}))
	defer hang.Close()
	r := NewStreamsResolver(100 * time.Millisecond)
	start := time.Now()
	_, err := r.ResolveImageDigests(context.Background(), hang.URL, "ubuntu/24.04")
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("should time out")
	}
	if elapsed > 500*time.Millisecond {
		t.Fatalf("timeout not honored; elapsed = %v", elapsed)
	}
}

// --- DigestMatchesSet helper tests ---

func TestDigestMatchesSet_HappyPath(t *testing.T) {
	pub := []string{
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	}
	if !DigestMatchesSet("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", pub) {
		t.Fatal("exact match should succeed")
	}
}

func TestDigestMatchesSet_TolerantPrefixAndCase(t *testing.T) {
	// Operators paste digests in lots of shapes. The
	// match function normalizes both sides so callers
	// don't have to.
	pub := []string{"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}
	for _, candidate := range []string{
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"SHA256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		" sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa ",
	} {
		if !DigestMatchesSet(candidate, pub) {
			t.Errorf("candidate %q should match", candidate)
		}
	}
}

func TestDigestMatchesSet_RejectsMalformed(t *testing.T) {
	pub := []string{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	for _, bad := range []string{
		"",
		"sha256:",
		"short",
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaXX", // too long
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaagh",  // non-hex
		"md5:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	} {
		if DigestMatchesSet(bad, pub) {
			t.Errorf("malformed digest %q should not match", bad)
		}
	}
}

func TestDigestMatchesSet_EmptyPublishedSet(t *testing.T) {
	// No published digests = never matches. The Phase B
	// gate uses this to refuse "alias not found" cases.
	if DigestMatchesSet("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", nil) {
		t.Fatal("empty published set must never match")
	}
	if DigestMatchesSet("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", []string{}) {
		t.Fatal("empty published slice must never match")
	}
}

// contains is a tiny string-slice helper. Stays local
// rather than reaching for slices.Contains so the package
// compiles on older Go SDKs the CI fleet still pins.
func contains(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}
