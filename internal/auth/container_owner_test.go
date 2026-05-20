package auth

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestOwnerFromContainerName(t *testing.T) {
	cases := map[string]struct {
		want   string
		wantOK bool
	}{
		"alice-container":         {"alice", true},
		"bob-with-dash-container": {"bob-with-dash", true},
		"":                        {"", false},
		"   ":                     {"", false},
		"alice":                   {"", false},
		"-container":              {"", false},
		"some-system-svc":         {"", false},
		"caddy":                   {"", false},
	}
	for in, want := range cases {
		t.Run(in, func(t *testing.T) {
			got, ok := OwnerFromContainerName(in)
			if got != want.want || ok != want.wantOK {
				t.Fatalf("OwnerFromContainerName(%q) = (%q,%v), want (%q,%v)",
					in, got, ok, want.want, want.wantOK)
			}
		})
	}
}

func TestAuthorizeContainerAccess_AdminAlwaysAllowed(t *testing.T) {
	ctx := ContextWithTestSubject(context.Background(), "ops", RoleAdmin)
	// Admin: works even on system containers.
	for _, name := range []string{"alice-container", "caddy", "victoria-metrics", ""} {
		t.Run(name, func(t *testing.T) {
			if err := AuthorizeContainerAccess(ctx, name); err != nil {
				t.Fatalf("admin should pass for %q; got %v", name, err)
			}
		})
	}
}

func TestAuthorizeContainerAccess_TenantOnlyOwnContainer(t *testing.T) {
	ctx := ContextWithTestSubject(context.Background(), "alice", "user")

	if err := AuthorizeContainerAccess(ctx, "alice-container"); err != nil {
		t.Fatalf("alice should access her own container; got %v", err)
	}
	err := AuthorizeContainerAccess(ctx, "bob-container")
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("alice on bob's container: got %v want PermissionDenied", err)
	}
}

func TestAuthorizeContainerAccess_TenantDeniedOnSystemContainer(t *testing.T) {
	ctx := ContextWithTestSubject(context.Background(), "alice", "user")
	err := AuthorizeContainerAccess(ctx, "caddy")
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("non-admin on system container: got %v want PermissionDenied", err)
	}
}

func TestAuthorizeContainerAccess_NoSubjectReturnsUnauthenticated(t *testing.T) {
	err := AuthorizeContainerAccess(context.Background(), "alice-container")
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("missing subject: got %v want Unauthenticated", err)
	}
}
