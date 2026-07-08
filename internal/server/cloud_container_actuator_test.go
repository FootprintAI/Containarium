package server

import (
	"testing"

	"github.com/footprintai/containarium/internal/cloud"
)

func TestBuildContainerConfig(t *testing.T) {
	cfg := buildContainerConfig(cloud.ContainerSpec{
		LocalName: "cld-abc", Image: "ubuntu:24.04",
		RAMMB: 2048, DiskGB: 40, GPUCount: 1,
		SecretEnv: map[string]string{"API_TOKEN": "shh"},
	})
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
	cfg := buildContainerConfig(cloud.ContainerSpec{LocalName: "cld-x", Image: "alpine"})
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
