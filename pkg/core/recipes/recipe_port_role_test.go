package recipes

import (
	"strings"
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/protobuf/proto"
)

// #3464: a recipe port can name itself the in-box auth-proxy entry point.
func TestPortRoleParsingAndValidation(t *testing.T) {
	const head = "recipes:\n  - id: r\n    image: a\n    ports:\n"
	tests := []struct {
		name    string
		ports   string
		wantErr string // substring; "" means must load
		want    []pb.RecipePortRole
	}{
		{"unset role stays unspecified",
			"      - container_port: 80\n        subdomain: a\n",
			"", []pb.RecipePortRole{pb.RecipePortRole_RECIPE_PORT_ROLE_UNSPECIFIED}},
		{"auth_proxy parsed",
			"      - container_port: 80\n        subdomain: a\n        role: auth_proxy\n",
			"", []pb.RecipePortRole{pb.RecipePortRole_RECIPE_PORT_ROLE_AUTH_PROXY}},
		{"auth_proxy on explicit http",
			"      - container_port: 80\n        subdomain: a\n        protocol: http\n        role: auth_proxy\n",
			"", []pb.RecipePortRole{pb.RecipePortRole_RECIPE_PORT_ROLE_AUTH_PROXY}},
		{"one auth_proxy among several ports",
			"      - container_port: 80\n        subdomain: a\n      - container_port: 81\n        subdomain: b\n        role: auth_proxy\n",
			"", []pb.RecipePortRole{pb.RecipePortRole_RECIPE_PORT_ROLE_UNSPECIFIED, pb.RecipePortRole_RECIPE_PORT_ROLE_AUTH_PROXY}},
		{"two auth_proxy ports rejected",
			"      - container_port: 80\n        subdomain: a\n        role: auth_proxy\n      - container_port: 81\n        subdomain: b\n        role: auth_proxy\n",
			"more than one port", nil},
		{"auth_proxy on tcp rejected",
			"      - container_port: 80\n        protocol: tcp\n        role: auth_proxy\n",
			"HTTP-routed", nil},
		{"auth_proxy on udp rejected",
			"      - container_port: 80\n        protocol: udp\n        role: auth_proxy\n",
			"HTTP-routed", nil},
		{"unknown role rejected",
			"      - container_port: 80\n        subdomain: a\n        role: admin\n",
			"unsupported role", nil},
		{"enum-style role string rejected",
			"      - container_port: 80\n        subdomain: a\n        role: RECIPE_PORT_ROLE_AUTH_PROXY\n",
			"unsupported role", nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := New()
			err := m.LoadFromBytes([]byte(head + tc.ports))
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("LoadFromBytes: %v", err)
			}
			r, _ := m.Get("r")
			if len(r.Ports) != len(tc.want) {
				t.Fatalf("ports = %d, want %d", len(r.Ports), len(tc.want))
			}
			for i, w := range tc.want {
				if r.Ports[i].Role != w {
					t.Errorf("port %d role = %v, want %v", i, r.Ports[i].Role, w)
				}
			}
		})
	}
}

// Built-in recipes whose exposed port is fronted by an in-box auth proxy must
// say so; every other built-in port stays unspecified.
func TestBuiltinRecipePortRoles(t *testing.T) {
	m := New()
	if err := m.LoadEmbedded(); err != nil {
		t.Fatal(err)
	}
	authProxyPort := map[string]int32{
		"slides-agent":    8080,
		"agent-workspace": 8080,
		"librechat":       8080,
	}
	for _, r := range m.List() {
		for _, p := range r.Ports {
			want := pb.RecipePortRole_RECIPE_PORT_ROLE_UNSPECIFIED
			if cp, ok := authProxyPort[r.Id]; ok && cp == p.ContainerPort {
				want = pb.RecipePortRole_RECIPE_PORT_ROLE_AUTH_PROXY
			}
			if p.Role != want {
				t.Errorf("recipe %q port %d role = %v, want %v", r.Id, p.ContainerPort, p.Role, want)
			}
		}
	}
	for id := range authProxyPort {
		if _, err := m.Get(id); err != nil {
			t.Errorf("expected built-in recipe %q: %v", id, err)
		}
	}
}

func TestRecipePortRoleProtoRoundTrip(t *testing.T) {
	in := &pb.RecipePort{ContainerPort: 8080, Subdomain: "x", Role: pb.RecipePortRole_RECIPE_PORT_ROLE_AUTH_PROXY}
	b, err := proto.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out pb.RecipePort
	if err := proto.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	if out.Role != pb.RecipePortRole_RECIPE_PORT_ROLE_AUTH_PROXY {
		t.Fatalf("role = %v after round trip", out.Role)
	}
	if pb.RecipePortRole_RECIPE_PORT_ROLE_AUTH_PROXY.String() != "RECIPE_PORT_ROLE_AUTH_PROXY" {
		t.Fatal("enum name drifted")
	}
	// Unset role must marshal to nothing (additive on the wire).
	b, _ = proto.Marshal(&pb.RecipePort{ContainerPort: 1})
	var z pb.RecipePort
	_ = proto.Unmarshal(b, &z)
	if z.Role != pb.RecipePortRole_RECIPE_PORT_ROLE_UNSPECIFIED {
		t.Fatal("unset role not unspecified")
	}
}
