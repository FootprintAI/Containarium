package containariumotel

import (
	"context"
	"testing"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/resource"
)

func TestBuildResource_ContainariumAttrs(t *testing.T) {
	clearEnv(t)
	ctx := context.Background()
	cfg := DistroConfig{
		ContainerID:    "alice-container",
		BackendID:      "node-7",
		TenantID:       "alice",
		ServiceVersion: "v1.2.3",
	}
	res, err := buildResource(ctx, cfg, nil, "0.20.0")
	if err != nil {
		t.Fatalf("buildResource: %v", err)
	}
	want := map[string]string{
		"container.id":        "alice-container",
		"backend.id":          "node-7",
		"service.namespace":   "alice",
		"service.version":     "v1.2.3",
		"containarium.distro": "go/0.20.0",
	}
	for k, v := range want {
		got := attrValueString(res, k)
		if got != v {
			t.Errorf("attr %q = %q, want %q", k, got, v)
		}
	}
}

func TestBuildResource_DistroStampDefended(t *testing.T) {
	clearEnv(t)
	ctx := context.Background()
	res, err := buildResource(ctx, DistroConfig{}, map[string]string{
		"containarium.distro": "evil/override",
	}, "0.20.0")
	if err != nil {
		t.Fatalf("buildResource: %v", err)
	}
	got := attrValueString(res, "containarium.distro")
	if got != "go/0.20.0" {
		t.Errorf("containarium.distro = %q, want go/0.20.0 (defended)", got)
	}
}

func TestBuildResource_OTELEnvWinsOverContainarium(t *testing.T) {
	clearEnv(t)
	// User-set OTEL_RESOURCE_ATTRIBUTES should override Containarium
	// env attrs (precedence row #4 > #3).
	t.Setenv("OTEL_RESOURCE_ATTRIBUTES", "container.id=overridden,extra.key=hello")
	ctx := context.Background()
	cfg := DistroConfig{
		ContainerID: "alice-container",
		TenantID:    "alice",
	}
	res, err := buildResource(ctx, cfg, nil, "0.20.0")
	if err != nil {
		t.Fatalf("buildResource: %v", err)
	}
	if got := attrValueString(res, "container.id"); got != "overridden" {
		t.Errorf("container.id = %q, want overridden", got)
	}
	if got := attrValueString(res, "extra.key"); got != "hello" {
		t.Errorf("extra.key = %q, want hello", got)
	}
	// Non-overridden Containarium attr survives.
	if got := attrValueString(res, "service.namespace"); got != "alice" {
		t.Errorf("service.namespace = %q, want alice", got)
	}
}

func TestBuildResource_ExtraAttrsWinOverEnv(t *testing.T) {
	clearEnv(t)
	t.Setenv("OTEL_RESOURCE_ATTRIBUTES", "k=from-env")
	ctx := context.Background()
	res, err := buildResource(ctx, DistroConfig{}, map[string]string{
		"k": "from-extra",
	}, "0.20.0")
	if err != nil {
		t.Fatalf("buildResource: %v", err)
	}
	if got := attrValueString(res, "k"); got != "from-extra" {
		t.Errorf("k = %q, want from-extra", got)
	}
}

func TestBuildResource_MissingAttrsOmitted(t *testing.T) {
	clearEnv(t)
	ctx := context.Background()
	cfg := DistroConfig{ContainerID: "alice-container"}
	res, err := buildResource(ctx, cfg, nil, "0.20.0")
	if err != nil {
		t.Fatalf("buildResource: %v", err)
	}
	for _, k := range []string{"backend.id", "service.namespace", "service.version"} {
		if got := attrValueString(res, k); got != "" {
			t.Errorf("attr %q = %q, want absent", k, got)
		}
	}
}

// attrValueString reads a resource attribute by key. Returns "" if
// absent — callers test for absence by checking against "".
func attrValueString(res *resource.Resource, key string) string {
	iter := res.Iter()
	for iter.Next() {
		kv := iter.Attribute()
		if string(kv.Key) == key {
			return kv.Value.AsString()
		}
	}
	return ""
}

// _ ensures the attribute import is used even if no test references
// it directly (linters complain otherwise).
var _ = attribute.String
