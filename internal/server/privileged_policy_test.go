package server

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/footprintai/containarium/internal/auth"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Phase 3.2 — privileged-Podman policy gate (audit A-HIGH-3).

func resetPrivilegedPolicy(t *testing.T) {
	t.Helper()
	privilegedPolicy = PrivilegedPolicyAll
	privilegedPolicyErr = nil
	privilegedPolicyOnce = sync.Once{}
}

// TestPrivilegedPolicy_DefaultIsAll preserves the backwards-compatible default
// when the policy variable is genuinely absent.
func TestPrivilegedPolicy_DefaultIsAll(t *testing.T) {
	unsetPrivilegedPolicyEnv(t)
	resetPrivilegedPolicy(t)
	if got := loadPrivilegedPolicy(); got != PrivilegedPolicyAll {
		t.Fatalf("policy = %v, want PrivilegedPolicyAll (backwards-compat default)", got)
	}
}

func TestPrivilegedPolicy_ParsesAdminOnly(t *testing.T) {
	t.Setenv(privilegedPolicyEnv, "admin-only")
	resetPrivilegedPolicy(t)
	if got := loadPrivilegedPolicy(); got != PrivilegedPolicyAdminOnly {
		t.Fatalf("policy = %v, want PrivilegedPolicyAdminOnly", got)
	}
}

func TestPrivilegedPolicy_ParsesDisabled(t *testing.T) {
	t.Setenv(privilegedPolicyEnv, "disabled")
	resetPrivilegedPolicy(t)
	if got := loadPrivilegedPolicy(); got != PrivilegedPolicyDisabled {
		t.Fatalf("policy = %v, want PrivilegedPolicyDisabled", got)
	}
}

func TestAuthorizePrivilegedPodman_AllPolicy(t *testing.T) {
	t.Setenv(privilegedPolicyEnv, "all")
	resetPrivilegedPolicy(t)

	// "all" accepts every caller, no role check needed.
	allowed, err := authorizePrivilegedPodman(context.Background())
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if !allowed {
		t.Fatal("policy=all must allow privileged")
	}
}

func TestAuthorizePrivilegedPodman_AdminOnly_NonAdminRejected(t *testing.T) {
	t.Setenv(privilegedPolicyEnv, "admin-only")
	resetPrivilegedPolicy(t)

	ctx := auth.ContextWithTestSubject(context.Background(), "alice", "user")
	allowed, err := authorizePrivilegedPodman(ctx)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("non-admin must be denied; got %v (%v)", status.Code(err), err)
	}
	if allowed {
		t.Fatal("non-admin must not be allowed")
	}
}

func TestAuthorizePrivilegedPodman_AdminOnly_AdminAllowed(t *testing.T) {
	t.Setenv(privilegedPolicyEnv, "admin-only")
	resetPrivilegedPolicy(t)

	ctx := auth.ContextWithSystemIdentity(context.Background())
	allowed, err := authorizePrivilegedPodman(ctx)
	if err != nil {
		t.Fatalf("admin must pass: %v", err)
	}
	if !allowed {
		t.Fatal("admin must be allowed")
	}
}

func TestAuthorizePrivilegedPodman_Disabled_DowngradesEvenForAdmin(t *testing.T) {
	t.Setenv(privilegedPolicyEnv, "disabled")
	resetPrivilegedPolicy(t)

	ctx := auth.ContextWithSystemIdentity(context.Background())
	allowed, err := authorizePrivilegedPodman(ctx)
	if err != nil {
		t.Fatalf("disabled policy must not error: %v", err)
	}
	if allowed {
		t.Fatal("disabled policy must downgrade to unprivileged even for admin")
	}
}

// #2299 — a value that is set but unrecognised (after the usual trim +
// lower-case normalisation) must fail closed, never fall back to the
// permissive `all`. Case and whitespace variants of the three valid
// spellings stay valid, as they are on main.

// unsetPrivilegedPolicyEnv removes the variable for the test (t.Setenv first
// so the original value is restored afterwards).
func unsetPrivilegedPolicyEnv(t *testing.T) {
	t.Helper()
	t.Setenv(privilegedPolicyEnv, "")
	if err := os.Unsetenv(privilegedPolicyEnv); err != nil {
		t.Fatalf("unsetenv: %v", err)
	}
}

// normalisedPrivilegedPolicyValues are case and whitespace variants of the
// valid spellings. Normalisation (TrimSpace + ToLower) resolves each to its
// policy.
var normalisedPrivilegedPolicyValues = []struct {
	raw  string
	want PrivilegedPolicy
}{
	{"ALL", PrivilegedPolicyAll},
	{"All", PrivilegedPolicyAll},
	{" all", PrivilegedPolicyAll},
	{"all\t", PrivilegedPolicyAll},
	{"ADMIN-ONLY", PrivilegedPolicyAdminOnly},
	{"Admin-Only", PrivilegedPolicyAdminOnly},
	{" admin-only ", PrivilegedPolicyAdminOnly},
	{"Disabled ", PrivilegedPolicyDisabled},
	{"Disabled", PrivilegedPolicyDisabled},
	{"DISABLED", PrivilegedPolicyDisabled},
	{" disabled", PrivilegedPolicyDisabled},
	{"disabled ", PrivilegedPolicyDisabled},
	{"\tdisabled", PrivilegedPolicyDisabled},
	{"disabled\n", PrivilegedPolicyDisabled},
}

// malformedPrivilegedPolicyValues stay unrecognised after normalisation.
// Each must be refused, including a present-but-blank value (#2345).
var malformedPrivilegedPolicyValues = []string{
	"",
	" ",
	"\t",
	"\n",
	"\t\n ",
	"none",
	"NONE",
	" none ",
	"off",
	"false",
	"no",
	"0",
	"alll",
	"admin_only",
	"adminonly",
	"admin only",
	"Admin_Only",
	"disable",
	"\tdisable",
	"enabled",
	"privileged",
}

// TestParsePrivilegedPolicy_ValidAndUnset accepts the three policies and their
// normalised variants, reserving the default for an unset variable.
func TestParsePrivilegedPolicy_ValidAndUnset(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		set  bool
		want PrivilegedPolicy
	}{
		{"unset keeps the backwards-compat default", "", false, PrivilegedPolicyAll},
		{"all", "all", true, PrivilegedPolicyAll},
		{"admin-only", "admin-only", true, PrivilegedPolicyAdminOnly},
		{"disabled", "disabled", true, PrivilegedPolicyDisabled},
	}
	for _, v := range normalisedPrivilegedPolicyValues {
		cases = append(cases, struct {
			name string
			raw  string
			set  bool
			want PrivilegedPolicy
		}{fmt.Sprintf("normalised %q", v.raw), v.raw, true, v.want})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parsePrivilegedPolicy(tc.raw, tc.set)
			if err != nil {
				t.Fatalf("parsePrivilegedPolicy(%q, %v) err = %v, want nil", tc.raw, tc.set, err)
			}
			if got != tc.want {
				t.Fatalf("parsePrivilegedPolicy(%q, %v) = %v, want %v", tc.raw, tc.set, got, tc.want)
			}
		})
	}
}

func TestParsePrivilegedPolicy_MalformedFailsClosed(t *testing.T) {
	for _, raw := range malformedPrivilegedPolicyValues {
		t.Run(fmt.Sprintf("%q", raw), func(t *testing.T) {
			got, err := parsePrivilegedPolicy(raw, true)
			if err == nil {
				t.Fatalf("parsePrivilegedPolicy(%q) err = nil, want a refusal", raw)
			}
			if !strings.Contains(err.Error(), privilegedPolicyEnv) {
				t.Fatalf("error %q must name %s so the operator knows what to fix", err, privilegedPolicyEnv)
			}
			if got != PrivilegedPolicyDisabled {
				t.Fatalf("parsePrivilegedPolicy(%q) = %v, want PrivilegedPolicyDisabled (fail closed)", raw, got)
			}
		})
	}
}

// TestValidatePrivilegedPolicyEnv accepts unset and valid settings at startup
// while refusing present-but-blank and unrecognised values.
func TestValidatePrivilegedPolicyEnv(t *testing.T) {
	t.Run("unset", func(t *testing.T) {
		unsetPrivilegedPolicyEnv(t)
		resetPrivilegedPolicy(t)
		if err := validatePrivilegedPolicyEnv(); err != nil {
			t.Fatalf("unset must start: %v", err)
		}
	})
	valid := []string{"all", "admin-only", "disabled"}
	for _, v := range normalisedPrivilegedPolicyValues {
		valid = append(valid, v.raw)
	}
	for _, v := range valid {
		t.Run(fmt.Sprintf("valid %q", v), func(t *testing.T) {
			t.Setenv(privilegedPolicyEnv, v)
			resetPrivilegedPolicy(t)
			if err := validatePrivilegedPolicyEnv(); err != nil {
				t.Fatalf("%q must start: %v", v, err)
			}
		})
	}
	for _, raw := range malformedPrivilegedPolicyValues {
		t.Run(fmt.Sprintf("malformed %q", raw), func(t *testing.T) {
			t.Setenv(privilegedPolicyEnv, raw)
			resetPrivilegedPolicy(t)
			if err := validatePrivilegedPolicyEnv(); err == nil {
				t.Fatalf("%q must refuse to start", raw)
			}
		})
	}
}

// Normalised variants gate callers exactly like the canonical spelling.
func TestAuthorizePrivilegedPodman_NormalisedVariants(t *testing.T) {
	admin := auth.ContextWithSystemIdentity(context.Background())
	nonAdmin := auth.ContextWithTestSubject(context.Background(), "alice", "user")
	for _, v := range normalisedPrivilegedPolicyValues {
		t.Run(fmt.Sprintf("%q", v.raw), func(t *testing.T) {
			t.Setenv(privilegedPolicyEnv, v.raw)
			resetPrivilegedPolicy(t)
			adminAllowed, adminErr := authorizePrivilegedPodman(admin)
			userAllowed, userErr := authorizePrivilegedPodman(nonAdmin)
			switch v.want {
			case PrivilegedPolicyAll:
				if !adminAllowed || adminErr != nil || !userAllowed || userErr != nil {
					t.Fatalf("all: admin=(%v,%v) user=(%v,%v), want both (true,nil)", adminAllowed, adminErr, userAllowed, userErr)
				}
			case PrivilegedPolicyAdminOnly:
				if !adminAllowed || adminErr != nil {
					t.Fatalf("admin-only: admin=(%v,%v), want (true,nil)", adminAllowed, adminErr)
				}
				if userAllowed || status.Code(userErr) != codes.PermissionDenied {
					t.Fatalf("admin-only: non-admin=(%v,%v), want (false, PermissionDenied)", userAllowed, userErr)
				}
			case PrivilegedPolicyDisabled:
				if adminAllowed || adminErr != nil || userAllowed || userErr != nil {
					t.Fatalf("disabled: admin=(%v,%v) user=(%v,%v), want both (false,nil)", adminAllowed, adminErr, userAllowed, userErr)
				}
			}
		})
	}
}

// The lazy path (a caller that never ran the startup validation) must fail
// closed too: an unrecognised value never yields a privileged container,
// not even for an admin.
func TestAuthorizePrivilegedPodman_MalformedNeverPrivileged(t *testing.T) {
	for _, raw := range malformedPrivilegedPolicyValues {
		t.Run(fmt.Sprintf("%q", raw), func(t *testing.T) {
			t.Setenv(privilegedPolicyEnv, raw)
			resetPrivilegedPolicy(t)
			if got := loadPrivilegedPolicy(); got != PrivilegedPolicyDisabled {
				t.Fatalf("loadPrivilegedPolicy() = %v, want PrivilegedPolicyDisabled", got)
			}
			for name, ctx := range map[string]context.Context{
				"admin":     auth.ContextWithSystemIdentity(context.Background()),
				"non-admin": auth.ContextWithTestSubject(context.Background(), "alice", "user"),
				"anonymous": context.Background(),
			} {
				allowed, _ := authorizePrivilegedPodman(ctx)
				if allowed {
					t.Fatalf("%s caller got privileged Podman under unrecognised policy %q", name, raw)
				}
			}
		})
	}
}

func TestAuthorizePrivilegedPodman_UnsetStaysAll(t *testing.T) {
	unsetPrivilegedPolicyEnv(t)
	resetPrivilegedPolicy(t)
	allowed, err := authorizePrivilegedPodman(context.Background())
	if err != nil || !allowed {
		t.Fatalf("unset policy = (%v, %v), want (true, nil) — unset behaviour is unchanged", allowed, err)
	}
}

// TestNewDualServer_RefusesMalformedPrivilegedPolicy verifies that blank and
// unrecognised values fail at startup, before container initialisation.
func TestNewDualServer_RefusesMalformedPrivilegedPolicy(t *testing.T) {
	for _, raw := range malformedPrivilegedPolicyValues {
		t.Run(fmt.Sprintf("%q", raw), func(t *testing.T) {
			t.Setenv(privilegedPolicyEnv, raw)
			resetPrivilegedPolicy(t)

			ds, err := NewDualServer(&DualServerConfig{})
			if err == nil {
				t.Fatalf("NewDualServer started (%T) with an unrecognised %s=%q", ds, privilegedPolicyEnv, raw)
			}
			if !strings.Contains(err.Error(), privilegedPolicyEnv) {
				t.Fatalf("startup error %q must name %s", err, privilegedPolicyEnv)
			}
		})
	}
}
