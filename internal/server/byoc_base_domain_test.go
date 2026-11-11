//go:build !containarium_client

package server

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/footprintai/containarium/internal/app"
)

// A BYOC backend serves no management apex, whatever base domain it holds
// and however it got there (#2262); an unmarked host is unchanged.
func TestManagementRouteDomains_BYOCBackend(t *testing.T) {
	cases := []struct {
		name string
		cfg  *DualServerConfig
		want []string
	}{
		{"byoc with a stored base domain", &DualServerConfig{BaseDomain: "cp.example.com", BYOCBackend: true}, nil},
		{"byoc with public base domains", &DualServerConfig{BaseDomain: "cp.example.com", PublicBaseDomains: []string{"lab.example.com"}, BYOCBackend: true}, nil},
		{"unmarked host still serves its base domain", &DualServerConfig{BaseDomain: "example.org"}, []string{"example.org"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := managementRouteDomains(tc.cfg); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("managementRouteDomains = %v, want %v", got, tc.want)
			}
		})
	}
}

func mgmtRoute(domain string) *app.RouteRecord {
	return &app.RouteRecord{FullDomain: domain, Description: managementRouteDescription, CreatedBy: string(app.RouteCreatorSystem)}
}

// Only the daemon's own management routes are stale on a BYOC backend:
// ingress routes the cloud pushed, and anything a user created, stay.
func TestStaleManagementRoutes(t *testing.T) {
	routes := []*app.RouteRecord{
		mgmtRoute("lab.example.com"),
		mgmtRoute("cp.example.com"),
		{FullDomain: "app.tenant.cp.example.com", Description: "pushed by the cloud", CreatedBy: "cloud"},
		{FullDomain: "web.example.org", Description: managementRouteDescription, CreatedBy: "user"},
		{FullDomain: "other.example.org", Description: "some system route", CreatedBy: string(app.RouteCreatorSystem)},
		nil,
	}
	want := []string{"cp.example.com", "lab.example.com"}
	if got := staleManagementRoutes(routes); !reflect.DeepEqual(got, want) {
		t.Errorf("staleManagementRoutes = %v, want %v", got, want)
	}
	if got := staleManagementRoutes(nil); got != nil {
		t.Errorf("staleManagementRoutes(nil) = %v, want nil", got)
	}
}

type fakeManagementRouteStore struct {
	routes    []*app.RouteRecord
	listErr   error
	failOn    string
	deleted   []string
	listCalls int
}

func (f *fakeManagementRouteStore) List(_ context.Context, activeOnly bool) ([]*app.RouteRecord, error) {
	f.listCalls++
	if activeOnly {
		return nil, errors.New("must list inactive routes too: an inactive apex route still reappears")
	}
	return f.routes, f.listErr
}

func (f *fakeManagementRouteStore) Delete(_ context.Context, domain string) error {
	if domain == f.failOn {
		return errors.New("delete failed")
	}
	f.deleted = append(f.deleted, domain)
	return nil
}

func TestDropStaleManagementRoutes(t *testing.T) {
	t.Run("deletes only the management routes", func(t *testing.T) {
		s := &fakeManagementRouteStore{routes: []*app.RouteRecord{
			mgmtRoute("cp.example.com"),
			{FullDomain: "app.tenant.cp.example.com", CreatedBy: "cloud"},
		}}
		got := dropStaleManagementRoutes(context.Background(), s)
		if want := []string{"cp.example.com"}; !reflect.DeepEqual(got, want) || !reflect.DeepEqual(s.deleted, want) {
			t.Errorf("removed = %v, deleted = %v, want %v", got, s.deleted, want)
		}
	})
	t.Run("a failed delete does not stop the rest", func(t *testing.T) {
		s := &fakeManagementRouteStore{routes: []*app.RouteRecord{mgmtRoute("a.example.com"), mgmtRoute("b.example.com")}, failOn: "a.example.com"}
		got := dropStaleManagementRoutes(context.Background(), s)
		if want := []string{"b.example.com"}; !reflect.DeepEqual(got, want) {
			t.Errorf("removed = %v, want %v", got, want)
		}
	})
	t.Run("list error deletes nothing", func(t *testing.T) {
		s := &fakeManagementRouteStore{routes: []*app.RouteRecord{mgmtRoute("cp.example.com")}, listErr: errors.New("db down")}
		if got := dropStaleManagementRoutes(context.Background(), s); got != nil || s.deleted != nil {
			t.Errorf("removed = %v, deleted = %v, want nothing", got, s.deleted)
		}
	})
	t.Run("nothing stale is a no-op", func(t *testing.T) {
		s := &fakeManagementRouteStore{routes: []*app.RouteRecord{{FullDomain: "app.example.com", CreatedBy: "cloud"}}}
		if got := dropStaleManagementRoutes(context.Background(), s); got != nil || s.deleted != nil || s.listCalls != 1 {
			t.Errorf("removed = %v, deleted = %v, listCalls = %d", got, s.deleted, s.listCalls)
		}
	})
}
