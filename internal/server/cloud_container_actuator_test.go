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
	if cfg.GPU == nil {
		t.Error("GPUCount>0 should request GPU passthrough")
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

func TestBuildContainerConfig_MinimalOmitsDevices(t *testing.T) {
	cfg := buildContainerConfig(cloud.ContainerSpec{LocalName: "cld-x", Image: "alpine"})
	if cfg.Memory != "" {
		t.Errorf("no RAM → memory unset, got %q", cfg.Memory)
	}
	if cfg.Disk != nil {
		t.Errorf("no disk → Disk nil, got %+v", cfg.Disk)
	}
	if cfg.GPU != nil {
		t.Errorf("no GPU → GPU nil, got %+v", cfg.GPU)
	}
}
