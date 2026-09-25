package tracker

import (
	"context"
	"errors"
	"strings"
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// Route store tests (#2021) — real Postgres, same CONTAINARIUM_TEST_DSN
// convention as store_test.go. The FK + ON DELETE CASCADE is part of the
// contract, so it is exercised against the real database, not a mock.

// seedRouteConnection (re)creates a clean connection for user and returns
// its name. Routes hang off a connection by foreign key, so every route
// test needs one.
func seedRouteConnection(t *testing.T, ctx context.Context, store *Store, user, name string) {
	t.Helper()
	_, _ = store.pool.Exec(ctx, "DELETE FROM tracker_connections WHERE username = $1", user)
	if _, err := store.Set(ctx, Connection{
		Username: user, Name: name,
		Provider: pb.TrackerProvider_TRACKER_PROVIDER_GITHUB,
		Project:  "acme/widgets", CredentialSecret: "GH_TOKEN",
	}); err != nil {
		t.Fatalf("seed connection: %v", err)
	}
}

func TestRouteStore_SetGetListDelete(t *testing.T) {
	store, ctx := newTrackerTestStore(t)
	const user = "tracker-route-crud"
	seedRouteConnection(t, ctx, store, user, "default")

	// Set is an upsert keyed on (username, connection, scope): the table
	// below is applied in order, and the final state is what List must
	// return.
	sets := []struct {
		name  string
		route Route
	}{
		{"create product", Route{Username: user, Connection: "default", Scope: "product", SkillID: "product-define"}},
		{"create architecture", Route{Username: user, Connection: "default", Scope: "architecture", SkillID: "architect-design"}},
		{"idempotent repeat", Route{Username: user, Connection: "default", Scope: "product", SkillID: "product-define"}},
		{"repoint product", Route{Username: user, Connection: "default", Scope: "product", SkillID: "product-define-v2"}},
	}
	var firstProduct *Route
	for _, tt := range sets {
		got, err := store.SetRoute(ctx, tt.route)
		if err != nil {
			t.Fatalf("%s: SetRoute: %v", tt.name, err)
		}
		if got.SkillID != tt.route.SkillID || got.CreatedAt.IsZero() || got.UpdatedAt.IsZero() {
			t.Fatalf("%s: SetRoute = %+v, want skill %q and timestamps set", tt.name, got, tt.route.SkillID)
		}
		if tt.route.Scope == "product" {
			if firstProduct == nil {
				firstProduct = got
			} else if !got.CreatedAt.Equal(firstProduct.CreatedAt) {
				t.Errorf("%s: CreatedAt = %v, want unchanged %v (upsert, not a new row)", tt.name, got.CreatedAt, firstProduct.CreatedAt)
			}
		}
	}

	got, err := store.GetRoute(ctx, user, "default", "product")
	if err != nil {
		t.Fatalf("GetRoute: %v", err)
	}
	if got.SkillID != "product-define-v2" {
		t.Errorf("GetRoute skill = %q, want product-define-v2 (last Set wins)", got.SkillID)
	}

	list, err := store.ListRoutes(ctx, user, "default")
	if err != nil {
		t.Fatalf("ListRoutes: %v", err)
	}
	wantList := []struct{ scope, skill string }{
		{"architecture", "architect-design"}, // ordered by scope
		{"product", "product-define-v2"},
	}
	if len(list) != len(wantList) {
		t.Fatalf("ListRoutes = %+v, want %d routes", list, len(wantList))
	}
	for i, w := range wantList {
		if list[i].Scope != w.scope || list[i].SkillID != w.skill || list[i].Connection != "default" || list[i].Username != user {
			t.Errorf("ListRoutes[%d] = %+v, want scope=%s skill=%s", i, list[i], w.scope, w.skill)
		}
	}

	if err := store.DeleteRoute(ctx, user, "default", "product"); err != nil {
		t.Fatalf("DeleteRoute: %v", err)
	}
	if _, err := store.GetRoute(ctx, user, "default", "product"); !errors.Is(err, ErrRouteNotFound) {
		t.Fatalf("GetRoute after delete err = %v, want ErrRouteNotFound", err)
	}
	if err := store.DeleteRoute(ctx, user, "default", "product"); !errors.Is(err, ErrRouteNotFound) {
		t.Fatalf("DeleteRoute (already gone) err = %v, want ErrRouteNotFound", err)
	}

	// Another tenant never sees these routes, even for a same-named
	// connection.
	other, err := store.ListRoutes(ctx, user+"-other", "default")
	if err != nil {
		t.Fatalf("ListRoutes (other tenant): %v", err)
	}
	if len(other) != 0 {
		t.Errorf("ListRoutes (other tenant) = %+v, want empty", other)
	}
}

func TestRouteStore_CascadeOnConnectionDelete(t *testing.T) {
	store, ctx := newTrackerTestStore(t)
	const user = "tracker-route-cascade"
	seedRouteConnection(t, ctx, store, user, "default")

	for _, scope := range []string{"product", "architecture"} {
		if _, err := store.SetRoute(ctx, Route{Username: user, Connection: "default", Scope: scope, SkillID: "skill-" + scope}); err != nil {
			t.Fatalf("SetRoute %s: %v", scope, err)
		}
	}

	if err := store.Delete(ctx, user, "default"); err != nil {
		t.Fatalf("Delete connection: %v", err)
	}

	var n int
	if err := store.pool.QueryRow(ctx,
		"SELECT count(*) FROM tracker_routes WHERE username = $1 AND connection = $2", user, "default").Scan(&n); err != nil {
		t.Fatalf("count routes: %v", err)
	}
	if n != 0 {
		t.Fatalf("routes left after connection delete = %d, want 0 (ON DELETE CASCADE)", n)
	}

	// Re-creating a connection with the same name must not resurrect the
	// old routes.
	seedRouteConnection(t, ctx, store, user, "default")
	list, err := store.ListRoutes(ctx, user, "default")
	if err != nil {
		t.Fatalf("ListRoutes: %v", err)
	}
	if len(list) != 0 {
		t.Errorf("ListRoutes after reconnect = %+v, want empty", list)
	}
}

func TestRouteStore_SetOnMissingConnection_NotFound(t *testing.T) {
	store, ctx := newTrackerTestStore(t)
	const user = "tracker-route-missing-conn"
	_, _ = store.pool.Exec(ctx, "DELETE FROM tracker_connections WHERE username = $1", user)

	_, err := store.SetRoute(ctx, Route{Username: user, Connection: "nope", Scope: "product", SkillID: "product-define"})
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("SetRoute on a missing connection err = %v, want ErrNotFound (connection)", err)
	}
}

func TestRouteStore_SetRejectsInvalidInput(t *testing.T) {
	store, ctx := newTrackerTestStore(t)
	const user = "tracker-route-invalid"
	seedRouteConnection(t, ctx, store, user, "default")

	tests := []struct {
		name  string
		route Route
	}{
		{"no username", Route{Connection: "default", Scope: "product", SkillID: "s"}},
		{"no connection", Route{Username: user, Scope: "product", SkillID: "s"}},
		{"no skill", Route{Username: user, Connection: "default", Scope: "product"}},
		{"bad scope", Route{Username: user, Connection: "default", Scope: "scope:product", SkillID: "s"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := store.SetRoute(ctx, tt.route); err == nil {
				t.Fatalf("SetRoute(%+v) = nil error, want a validation error", tt.route)
			}
		})
	}
}

// TestValidateRouteScope is pure — no Postgres. A scope is the label
// suffix ("product" for the label "scope:product"), so the prefix itself,
// whitespace, and anything a forge would not accept in a label are
// rejected up front rather than stored as a route that can never match.
func TestValidateRouteScope(t *testing.T) {
	tests := []struct {
		scope   string
		wantErr bool
	}{
		{"product", false},
		{"architecture", false},
		{"qa-e2e", false},
		{"v2.release_notes", false},
		{"Product", false},
		{"", true},
		{"scope:product", true},
		{"has space", true},
		{"-leading-dash", true},
		{"a/b", true},
		{"tab\there", true},
		{strings.Repeat("a", 64), false},
		{strings.Repeat("a", 65), true},
	}
	for _, tt := range tests {
		err := ValidateRouteScope(tt.scope)
		if (err != nil) != tt.wantErr {
			t.Errorf("ValidateRouteScope(%q) err = %v, wantErr %v", tt.scope, err, tt.wantErr)
		}
	}
}
