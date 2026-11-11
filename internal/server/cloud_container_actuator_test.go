package server

import (
	"context"
	"errors"
	"testing"

	"github.com/footprintai/containarium/internal/app"
	"github.com/footprintai/containarium/internal/cloud"
	"github.com/footprintai/containarium/pkg/core/incus"
	"github.com/footprintai/containarium/pkg/core/incus/incustest"
)

// recordingRoutes is a routeLister that records Save calls.
type recordingRoutes struct{ saved []*app.RouteRecord }

func (r *recordingRoutes) ListByContainer(context.Context, string) ([]*app.RouteRecord, error) {
	return nil, nil
}
func (r *recordingRoutes) Delete(context.Context, string) error { return nil }
func (r *recordingRoutes) Save(_ context.Context, rec *app.RouteRecord) error {
	r.saved = append(r.saved, rec)
	return nil
}

// stampFailureFixture builds an actuator over a mock whose tenant-label stamp
// always fails, holding one existing container in the given state with the
// given (wrong or missing) tenant label.
func stampFailureFixture(state, tenant string) (*cloudContainerActuator, *incustest.MockBackend, *recordingRoutes, *[]string) {
	var calls []string
	mock := incustest.NewMockBackend()
	mock.Containers["cld-box"] = &incus.ContainerInfo{Name: "cld-box", State: state, Tenant: tenant, IPAddress: "10.0.0.5"}
	mock.SetConfigFunc = func(string, string, string) error { return errors.New("incus unavailable") }
	mock.StartContainerFunc = func(string) error { calls = append(calls, "start"); return nil }
	mock.StopContainerFunc = func(string, bool) error { calls = append(calls, "stop"); return nil }
	routes := &recordingRoutes{}
	return &cloudContainerActuator{incus: mock, routes: routes}, mock, routes, &calls
}

var stampFailureSpec = cloud.ContainerSpec{
	LocalName: "cld-box", OrgID: "org-1",
	Routes: []cloud.RouteSpec{{Domain: "box.example.test", TargetPort: 8080, Protocol: "http"}},
}

func TestEnsureRunning_StampFailureStoppedContainerNotStartedNorRouted(t *testing.T) {
	for _, tenant := range []string{"", "other-org"} { // missing and wrong label
		a, mock, routes, calls := stampFailureFixture("Stopped", tenant)
		err := a.EnsureRunning(context.Background(), stampFailureSpec)
		if err == nil {
			t.Errorf("tenant=%q: EnsureRunning returned nil, want an error", tenant)
		}
		if len(*calls) != 0 {
			t.Errorf("tenant=%q: container was started/stopped: %v", tenant, *calls)
		}
		if len(routes.saved) != 0 {
			t.Errorf("tenant=%q: routes applied despite failed stamp: %d", tenant, len(routes.saved))
		}
		if mock.Containers["cld-box"].State != "Stopped" {
			t.Errorf("tenant=%q: state = %q, want Stopped", tenant, mock.Containers["cld-box"].State)
		}
	}
}

func TestEnsureRunning_StampFailureRunningContainerDegradedAndLeftRunning(t *testing.T) {
	a, mock, routes, calls := stampFailureFixture("Running", "other-org")
	err := a.EnsureRunning(context.Background(), stampFailureSpec)
	if !errors.Is(err, cloud.ErrContainerDegraded) {
		t.Errorf("EnsureRunning err = %v, want cloud.ErrContainerDegraded", err)
	}
	if len(*calls) != 0 {
		t.Errorf("running container was stopped/restarted: %v", *calls)
	}
	if mock.Containers["cld-box"].State != "Running" {
		t.Errorf("state = %q, want Running", mock.Containers["cld-box"].State)
	}
	if len(routes.saved) != 0 {
		t.Errorf("routes applied despite failed stamp: %d", len(routes.saved))
	}
}

func TestEnsureRunning_CorrectLabelStillStartsAndRoutes(t *testing.T) {
	a, _, routes, calls := stampFailureFixture("Stopped", "org-1") // label fine: stamp not attempted
	if err := a.EnsureRunning(context.Background(), stampFailureSpec); err != nil {
		t.Fatalf("EnsureRunning: %v", err)
	}
	if len(*calls) != 1 || (*calls)[0] != "start" {
		t.Errorf("calls = %v, want [start]", *calls)
	}
	if len(routes.saved) != 1 {
		t.Errorf("routes saved = %d, want 1", len(routes.saved))
	}
}

func TestBuildContainerConfig(t *testing.T) {
	cfg := buildContainerConfig(cloud.ContainerSpec{
		LocalName: "cld-abc", Image: "ubuntu:24.04",
		RAMMB: 2048, DiskGB: 40, GPUCount: 1,
		SecretEnv: map[string]string{"API_TOKEN": "shh"},
	}, "default")
	if cfg.Env["API_TOKEN"] != "shh" {
		t.Errorf("secret_env not injected as container env: %v", cfg.Env)
	}
	if cfg.Name != "cld-abc" || cfg.Image != "ubuntu:24.04" {
		t.Errorf("name/image wrong: %+v", cfg)
	}
	if cfg.Memory != "2048MB" {
		t.Errorf("memory = %q, want 2048MB", cfg.Memory)
	}
	if cfg.Disk == nil || cfg.Disk.Size != "40GB" || cfg.Disk.Path != "/" || cfg.Disk.Pool != "default" {
		t.Errorf("disk wrong: %+v", cfg.Disk)
	}
	if len(cfg.GPUs) != 1 {
		t.Errorf("GPUCount>0 should request one GPU passthrough device, got %+v", cfg.GPUs)
	}
}

func TestRouteRecordFor(t *testing.T) {
	rec := routeRecordFor("cld-abc", "10.100.0.42", cloud.RouteSpec{
		Domain: "web.acme.example.com", TargetPort: 8080, Protocol: "http",
	})
	if rec.FullDomain != "web.acme.example.com" || rec.Subdomain != "web" {
		t.Errorf("domain/subdomain wrong: full=%q sub=%q", rec.FullDomain, rec.Subdomain)
	}
	if rec.TargetIP != "10.100.0.42" || rec.TargetPort != 8080 {
		t.Errorf("target wrong: %s:%d", rec.TargetIP, rec.TargetPort)
	}
	if rec.Protocol != "http" || rec.ContainerName != "cld-abc" {
		t.Errorf("proto/container wrong: %q %q", rec.Protocol, rec.ContainerName)
	}
	if rec.CreatedBy != cloudRouteCreatedBy || !rec.Active {
		t.Errorf("must be tagged cloud-created + active: by=%q active=%v", rec.CreatedBy, rec.Active)
	}
	// grpc passes through; anything else → http.
	if g := routeRecordFor("c", "1.2.3.4", cloud.RouteSpec{Domain: "g.x", TargetPort: 9, Protocol: "grpc"}); g.Protocol != "grpc" {
		t.Errorf("grpc protocol should pass through, got %q", g.Protocol)
	}
	if h := routeRecordFor("c", "1.2.3.4", cloud.RouteSpec{Domain: "h.x", TargetPort: 9, Protocol: "https"}); h.Protocol != "http" {
		t.Errorf("https should map to http edge, got %q", h.Protocol)
	}
}

// TestTenantLabelStale locks in the #780 follow-up fix: a container whose
// tenant label predates the labeling code (empty) or drifted from its
// current org must be flagged for re-stamping on every reconcile, not just
// at creation.
func TestTenantLabelStale(t *testing.T) {
	cases := []struct {
		name          string
		orgID         string
		currentTenant string
		want          bool
	}{
		{"already correct", "org-1", "org-1", false},
		{"never labeled", "org-1", "", true},
		{"stale from a reassignment", "org-1", "org-0", true},
		{"no org known yet — nothing to stamp", "", "", false},
		{"no org known yet — leave existing label alone", "", "org-1", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := tenantLabelStale(c.orgID, c.currentTenant); got != c.want {
				t.Errorf("tenantLabelStale(%q, %q) = %v, want %v", c.orgID, c.currentTenant, got, c.want)
			}
		})
	}
}

func TestBuildContainerConfig_MinimalOmitsDevices(t *testing.T) {
	cfg := buildContainerConfig(cloud.ContainerSpec{LocalName: "cld-x", Image: "alpine"}, "default")
	if cfg.Memory != "" {
		t.Errorf("no RAM → memory unset, got %q", cfg.Memory)
	}
	if cfg.Disk != nil {
		t.Errorf("no disk → Disk nil, got %+v", cfg.Disk)
	}
	if len(cfg.GPUs) != 0 {
		t.Errorf("no GPU → GPUs empty, got %+v", cfg.GPUs)
	}
}
