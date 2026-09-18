package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/footprintai/containarium/internal/app"
	"github.com/footprintai/containarium/internal/releases"
	"github.com/footprintai/containarium/pkg/core/incus"
	"github.com/footprintai/containarium/pkg/version"
)

// fakePrebuiltCaddyBackend is a minimal incus.Backend fake for the #1617
// prebuilt-Caddy install path: records every Exec/ExecWithOutput call so
// tests can assert on the shell script content without a real container.
type fakePrebuiltCaddyBackend struct {
	incus.Backend
	execCalls    [][]string
	execErr      error
	execOutput   string
	execOutErr   error
	execOutCalls [][]string
}

func (b *fakePrebuiltCaddyBackend) Exec(_ string, command []string) error {
	b.execCalls = append(b.execCalls, command)
	return b.execErr
}

func (b *fakePrebuiltCaddyBackend) ExecWithOutput(_ string, command []string) (string, string, error) {
	b.execOutCalls = append(b.execOutCalls, command)
	return b.execOutput, "", b.execOutErr
}

// setTestVersion pins pkg/version.Version for the duration of a test,
// restoring the original on cleanup — installPrebuiltCaddy derives the
// GitHub release tag from it.
func setTestVersion(t *testing.T, v string) {
	t.Helper()
	orig := version.Version
	version.Version = v
	t.Cleanup(func() { version.Version = orig })
}

// pointCaddyReleasesAt overrides releases.GitHubReleaseBaseURL for the
// duration of a test, restoring it on cleanup.
func pointCaddyReleasesAt(t *testing.T, url string) {
	t.Helper()
	orig := releases.GitHubReleaseBaseURL
	releases.GitHubReleaseBaseURL = url
	t.Cleanup(func() { releases.GitHubReleaseBaseURL = orig })
}

func TestInstallPrebuiltCaddy_DownloadsAndVerifiesChecksum(t *testing.T) {
	const binaryContent = "fake caddy binary bytes"
	sum := sha256.Sum256([]byte(binaryContent))
	sums := fmt.Sprintf("%s  %s\n", hex.EncodeToString(sum[:]), caddyReleaseBinaryName)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/SHA256SUMS.txt") {
			_, _ = w.Write([]byte(sums))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	pointCaddyReleasesAt(t, srv.URL)
	setTestVersion(t, "0.82.1")

	backend := &fakePrebuiltCaddyBackend{}
	cs := &CoreServices{incusClient: backend}

	if err := cs.installPrebuiltCaddy(context.Background()); err != nil {
		t.Fatalf("installPrebuiltCaddy: %v", err)
	}

	if len(backend.execCalls) != 1 {
		t.Fatalf("Exec called %d times, want 1", len(backend.execCalls))
	}
	script := strings.Join(backend.execCalls[0], " ")
	wantURL := srv.URL + "/v0.82.1/" + caddyReleaseBinaryName
	if !strings.Contains(script, wantURL) {
		t.Errorf("script does not reference the expected download URL %q:\n%s", wantURL, script)
	}
	wantSum := hex.EncodeToString(sum[:])
	if !strings.Contains(script, wantSum) {
		t.Errorf("script does not embed the expected checksum %q:\n%s", wantSum, script)
	}
}

func TestInstallPrebuiltCaddy_NoMatchingReleaseAsset(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	pointCaddyReleasesAt(t, srv.URL)
	setTestVersion(t, "0.1.0-predates-1617")

	backend := &fakePrebuiltCaddyBackend{}
	cs := &CoreServices{incusClient: backend}

	if err := cs.installPrebuiltCaddy(context.Background()); err == nil {
		t.Fatal("expected an error when no matching release asset exists")
	}
	if len(backend.execCalls) != 0 {
		t.Error("Exec should never be called when the SHA256SUMS fetch fails")
	}
}

func TestBuildCaddyFromSource_PinsVersionAndIncludesConfiguredProvider(t *testing.T) {
	t.Setenv("CONTAINARIUM_ACME_DNS_PROVIDER", "cloudflare")
	t.Setenv("CONTAINARIUM_ACME_DNS_PROVIDER_CONFIG", "")

	backend := &fakePrebuiltCaddyBackend{}
	cs := &CoreServices{incusClient: backend}

	if err := cs.buildCaddyFromSource(); err != nil {
		t.Fatalf("buildCaddyFromSource: %v", err)
	}

	var buildCmd string
	for _, call := range backend.execCalls {
		joined := strings.Join(call, " ")
		if strings.Contains(joined, "xcaddy build") {
			buildCmd = joined
		}
	}
	if buildCmd == "" {
		t.Fatal("no xcaddy build command was executed")
	}
	if !strings.Contains(buildCmd, "xcaddy build "+app.CaddyVersion) {
		t.Errorf("build command does not pin %s:\n%s", app.CaddyVersion, buildCmd)
	}
	if !strings.Contains(buildCmd, "github.com/mholt/caddy-l4") {
		t.Errorf("build command missing caddy-l4:\n%s", buildCmd)
	}
	if !strings.Contains(buildCmd, "github.com/caddy-dns/cloudflare") {
		t.Errorf("build command missing the configured provider's module:\n%s", buildCmd)
	}
}

func TestVerifyCaddyModules_NoProviderConfigured_NoOp(t *testing.T) {
	t.Setenv("CONTAINARIUM_ACME_DNS_PROVIDER", "")
	backend := &fakePrebuiltCaddyBackend{}
	cs := &CoreServices{incusClient: backend}

	if err := cs.verifyCaddyModules(); err != nil {
		t.Fatalf("verifyCaddyModules with no provider configured: %v", err)
	}
	if len(backend.execOutCalls) != 0 {
		t.Error("caddy list-modules should not run when DNS-01 isn't configured")
	}
}

func TestVerifyCaddyModules_ModulePresent(t *testing.T) {
	t.Setenv("CONTAINARIUM_ACME_DNS_PROVIDER", "cloudflare")
	t.Setenv("CONTAINARIUM_ACME_DNS_PROVIDER_CONFIG", "")
	backend := &fakePrebuiltCaddyBackend{execOutput: "dns.providers.cloudflare\nhttp.handlers.reverse_proxy\n"}
	cs := &CoreServices{incusClient: backend}

	if err := cs.verifyCaddyModules(); err != nil {
		t.Fatalf("verifyCaddyModules: %v", err)
	}
}

func TestVerifyCaddyModules_ModuleMissing_IsAnError(t *testing.T) {
	t.Setenv("CONTAINARIUM_ACME_DNS_PROVIDER", "cloudflare")
	t.Setenv("CONTAINARIUM_ACME_DNS_PROVIDER_CONFIG", "")
	backend := &fakePrebuiltCaddyBackend{execOutput: "http.handlers.reverse_proxy\n"}
	cs := &CoreServices{incusClient: backend}

	err := cs.verifyCaddyModules()
	if err == nil {
		t.Fatal("expected an error when the configured provider's module is missing")
	}
	if !strings.Contains(err.Error(), "dns.providers.cloudflare") {
		t.Errorf("error should name the missing module: %v", err)
	}
}
