package reqrate

import "testing"

func sampleByName(samples []Sample, name string) (Sample, bool) {
	for _, s := range samples {
		if s.ContainerName == name {
			return s, true
		}
	}
	return Sample{}, false
}

func TestResolver_JoinsHostToContainer(t *testing.T) {
	res := NewResolver(
		[]Route{
			{Host: "alice.example.com", UpstreamIP: "10.0.0.2"},
			{Host: "bob.example.com", UpstreamIP: "10.0.0.3"},
			{Host: "stale.example.com", UpstreamIP: "10.0.0.9"}, // no such container
		},
		[]Container{
			{Name: "alice", IP: "10.0.0.2", ContainerID: "uuid-a"},
			{Name: "bob", IP: "10.0.0.3", ContainerID: "uuid-b"},
			{Name: "noip", IP: ""}, // unroutable, skipped
		},
	)

	if c, ok := res.Resolve("alice.example.com"); !ok || c.ContainerID != "uuid-a" {
		t.Errorf("alice → %+v, ok=%v; want uuid-a", c, ok)
	}
	if c, ok := res.Resolve("ALICE.example.com"); !ok || c.ContainerID != "uuid-a" {
		t.Errorf("case-insensitive resolve failed: %+v ok=%v", c, ok)
	}
	if _, ok := res.Resolve("stale.example.com"); ok {
		t.Errorf("stale host resolved, want miss")
	}
	if _, ok := res.Resolve("unknown.example.com"); ok {
		t.Errorf("unknown host resolved, want miss")
	}
}

func TestBuild_SumsAliasesAndCountsDropped(t *testing.T) {
	res := NewResolver(
		[]Route{
			{Host: "alice.example.com", UpstreamIP: "10.0.0.2"},
			{Host: "alice-custom.com", UpstreamIP: "10.0.0.2"}, // alias → same container
			{Host: "bob.example.com", UpstreamIP: "10.0.0.3"},
		},
		[]Container{
			{Name: "alice", IP: "10.0.0.2", ContainerID: "uuid-a"},
			{Name: "bob", IP: "10.0.0.3", ContainerID: "uuid-b"},
		},
	)

	rates := map[string]float64{
		"alice.example.com": 0.2,
		"alice-custom.com":  0.3, // coalesces into alice → 0.5
		"bob.example.com":   0.1,
		"ghost.example.com": 9.9, // unresolved → dropped
	}

	samples, dropped := Build(rates, res)
	if dropped != 1 {
		t.Errorf("dropped = %d, want 1", dropped)
	}
	if len(samples) != 2 {
		t.Fatalf("len(samples) = %d, want 2 (%+v)", len(samples), samples)
	}
	// Sorted by name: alice before bob.
	if samples[0].ContainerName != "alice" || samples[1].ContainerName != "bob" {
		t.Errorf("samples not sorted by name: %+v", samples)
	}
	a, _ := sampleByName(samples, "alice")
	if a.RequestsPerSec != 0.5 || a.ContainerID != "uuid-a" {
		t.Errorf("alice sample = %+v, want rate 0.5 id uuid-a", a)
	}
	b, _ := sampleByName(samples, "bob")
	if b.RequestsPerSec != 0.1 {
		t.Errorf("bob rate = %v, want 0.1", b.RequestsPerSec)
	}
}

func TestBuild_KeysByNameWhenNoContainerID(t *testing.T) {
	// Standalone box: containers have no cloud_container_id. Build must still
	// coalesce aliases by name and produce a sample (recorded under name only).
	res := NewResolver(
		[]Route{
			{Host: "h1.example.com", UpstreamIP: "10.0.0.5"},
			{Host: "h2.example.com", UpstreamIP: "10.0.0.5"},
		},
		[]Container{{Name: "solo", IP: "10.0.0.5"}},
	)
	samples, dropped := Build(map[string]float64{
		"h1.example.com": 1,
		"h2.example.com": 2,
	}, res)
	if dropped != 0 {
		t.Errorf("dropped = %d, want 0", dropped)
	}
	if len(samples) != 1 || samples[0].ContainerName != "solo" || samples[0].RequestsPerSec != 3 {
		t.Fatalf("samples = %+v, want one solo @ 3", samples)
	}
	if samples[0].ContainerID != "" {
		t.Errorf("ContainerID = %q, want empty on standalone box", samples[0].ContainerID)
	}
}
