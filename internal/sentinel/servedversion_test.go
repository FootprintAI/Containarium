package sentinel

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestParseVersionOutput(t *testing.T) {
	cases := []struct {
		name, out, want string
		wantErr         bool
	}{
		{name: "release build", out: "Containarium v0.91.1\n", want: "0.91.1"},
		{name: "dev suffix", out: "Containarium v0.90.1-dev.1\n", want: "0.90.1-dev.1"},
		{name: "leading log noise", out: "some warning\nContainarium v0.91.1\n", want: "0.91.1"},
		{name: "empty", out: "", wantErr: true},
		{name: "unrelated output", out: "usage: foo\n", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseVersionOutput(tc.out)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("parseVersionOutput(%q) = %q, want error", tc.out, got)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("parseVersionOutput(%q) = %q, %v; want %q", tc.out, got, err, tc.want)
			}
		})
	}
}

// The version probe execs the served binary, so it must run once per distinct
// binary, not once per request.
func TestServedVersionCache_ProbesOncePerChecksum(t *testing.T) {
	path := filepath.Join(t.TempDir(), "containariumd")
	if err := os.WriteFile(path, []byte("build-a"), 0o600); err != nil {
		t.Fatal(err)
	}
	calls := 0
	c := &servedVersionCache{probe: func(context.Context, string) (string, error) {
		calls++
		return "0.91.1", nil
	}}

	for i := 0; i < 3; i++ {
		got, err := c.get(context.Background(), path)
		if err != nil || got.Version != "0.91.1" {
			t.Fatalf("get = %+v, %v", got, err)
		}
	}
	if calls != 1 {
		t.Fatalf("probe calls = %d, want 1 for an unchanged binary", calls)
	}

	if err := os.WriteFile(path, []byte("build-b"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := c.get(context.Background(), path); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("probe calls = %d, want 2 after the binary changed", calls)
	}
}

func TestServedVersionCache_ProbeErrorNotCached(t *testing.T) {
	path := filepath.Join(t.TempDir(), "containariumd")
	if err := os.WriteFile(path, []byte("build-a"), 0o600); err != nil {
		t.Fatal(err)
	}
	fail := true
	c := &servedVersionCache{probe: func(context.Context, string) (string, error) {
		if fail {
			return "", errors.New("boom")
		}
		return "0.91.1", nil
	}}
	if _, err := c.get(context.Background(), path); err == nil {
		t.Fatal("want error from failing probe")
	}
	fail = false
	got, err := c.get(context.Background(), path)
	if err != nil || got.Version != "0.91.1" {
		t.Fatalf("after recovery get = %+v, %v", got, err)
	}
}

// End to end through the real route table: /containarium/version reports the
// SERVED file's version (not this process's build), and follows an in-place
// swap with no sentinel restart — the case /sentinel/version gets wrong.
func TestContainariumVersionRoute_ReportsServedBinary(t *testing.T) {
	path := filepath.Join(t.TempDir(), "containariumd")
	writeFakeBinary := func(v string) {
		t.Helper()
		script := "#!/bin/sh\n[ \"$1\" = version ] && echo 'Containarium v" + v + "'\n"
		if err := os.WriteFile(path, []byte(script), 0o700); err != nil { // #nosec G306 -- test fixture must be executable
			t.Fatal(err)
		}
	}
	writeFakeBinary("9.9.1")

	m := &Manager{backends: NewBackendPool(), primaries: NewPrimaryRegistry()}
	srv := httptest.NewServer(buildBinaryServerMux(path, m))
	t.Cleanup(srv.Close)

	fetch := func() servedVersionResponse {
		t.Helper()
		resp, err := http.Get(srv.URL + "/containarium/version")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d", resp.StatusCode)
		}
		var out servedVersionResponse
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			t.Fatal(err)
		}
		return out
	}

	first := fetch()
	if first.Version != "9.9.1" || first.Checksum == "" {
		t.Fatalf("first = %+v, want version 9.9.1 with a checksum", first)
	}

	writeFakeBinary("9.9.2")
	second := fetch()
	if second.Version != "9.9.2" {
		t.Fatalf("after in-place swap version = %q, want 9.9.2", second.Version)
	}
	if second.Checksum == first.Checksum {
		t.Fatal("checksum did not change after swap")
	}
}

func TestContainariumVersionRoute_MissingBinary(t *testing.T) {
	m := &Manager{backends: NewBackendPool(), primaries: NewPrimaryRegistry()}
	srv := httptest.NewServer(buildBinaryServerMux("/nonexistent/containarium", m))
	t.Cleanup(srv.Close)
	resp, err := http.Get(srv.URL + "/containarium/version")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Fatal("want non-200 when the served binary is missing")
	}
}
