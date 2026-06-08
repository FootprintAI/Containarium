package server

import (
	"strings"
	"sync"
	"testing"
)

// Phase 3.1 — image-registry allowlist (audit B-HIGH-1).
//
// loadImageAllowlist caches its result via sync.Once, so each test
// case operates on a freshly-allocated allowlist by resetting the
// package-level state. (The production code reads the env var
// once per process — these tests just verify the parsing +
// matching logic.)

func resetImageAllowlist(t *testing.T) {
	t.Helper()
	imageAllowlist = nil
	imageAllowlistAll = false
	// Replace the Once so it'll re-fire on next call.
	imageAllowlistOnce = sync.Once{}
}

func TestImageRegistryPrefix(t *testing.T) {
	cases := map[string]string{
		"ubuntu:22.04":                     "ubuntu",
		"images:ubuntu/22.04/cloud":        "images",
		"incus:noble":                      "incus",
		"https://images.example.com/x.img": "https://images.example.com",
		"http://internal/foo":              "http://internal",
		"ubuntu":                           "ubuntu", // bare name → default remote
		"22.04":                            "ubuntu",
		"images/ubuntu/22.04":              "", // path without remote → no prefix → rejected
		"":                                 "",
	}
	for in, want := range cases {
		t.Run(in, func(t *testing.T) {
			got := imageRegistryPrefix(in)
			if got != want {
				t.Errorf("prefix(%q) = %q, want %q", in, got, want)
			}
		})
	}
}

func TestValidateImageRegistry_EmptyAllowlistAcceptsAll(t *testing.T) {
	t.Setenv(allowedImageRegistriesEnv, "")
	resetImageAllowlist(t)

	cases := []string{"ubuntu:22.04", "https://random.example", "anything"}
	for _, in := range cases {
		if err := validateImageRegistry(in); err != nil {
			t.Errorf("unset allowlist must accept %q: %v", in, err)
		}
	}
}

func TestValidateImageRegistry_RejectsUnknownRegistry(t *testing.T) {
	t.Setenv(allowedImageRegistriesEnv, "ubuntu,images")
	resetImageAllowlist(t)

	if err := validateImageRegistry("docker:registry.attacker.example/evil:latest"); err == nil {
		t.Fatal("unknown registry must be rejected")
	}
	if err := validateImageRegistry("https://attacker.example/img"); err == nil {
		t.Fatal("URL outside allowlist must be rejected")
	}
}

func TestValidateImageRegistry_AcceptsAllowedRegistry(t *testing.T) {
	t.Setenv(allowedImageRegistriesEnv, "ubuntu,images,incus")
	resetImageAllowlist(t)

	cases := []string{
		"ubuntu:22.04",
		"images:debian/12",
		"incus:noble",
		"ubuntu", // bare name → default ubuntu remote
	}
	for _, in := range cases {
		if err := validateImageRegistry(in); err != nil {
			t.Errorf("%q should be accepted under allowlist {ubuntu, images, incus}: %v", in, err)
		}
	}
}

func TestValidateImageRegistry_ErrorMessageNamesEnvVar(t *testing.T) {
	t.Setenv(allowedImageRegistriesEnv, "ubuntu")
	resetImageAllowlist(t)

	err := validateImageRegistry("docker:bad")
	if err == nil {
		t.Fatal("expected rejection")
	}
	if !strings.Contains(err.Error(), allowedImageRegistriesEnv) {
		t.Fatalf("error should name the env var so the operator can fix: %v", err)
	}
}

func TestValidateImageRegistry_EmptyImageStillAccepted(t *testing.T) {
	t.Setenv(allowedImageRegistriesEnv, "ubuntu")
	resetImageAllowlist(t)

	// Empty image is permitted — the manager substitutes a default
	// based on OSType. Don't break that flow.
	if err := validateImageRegistry(""); err != nil {
		t.Fatalf("empty image must be accepted: %v", err)
	}
}
