package traffic

import "testing"

func statByName(stats []EgressStat, name string) (EgressStat, bool) {
	for _, s := range stats {
		if s.ContainerName == name {
			return s, true
		}
	}
	return EgressStat{}, false
}

func TestAggregateEgress_DistinctDestinationsAndCount(t *testing.T) {
	ids := map[string]string{"crawler": "uuid-c", "normal": "uuid-n"}
	idForName := func(n string) string { return ids[n] }

	conns := []egressConn{
		// "crawler": 5 connections to 4 distinct destinations (one repeat).
		{"crawler", "1.1.1.1"},
		{"crawler", "2.2.2.2"},
		{"crawler", "3.3.3.3"},
		{"crawler", "4.4.4.4"},
		{"crawler", "1.1.1.1"}, // repeat dst — still one distinct
		// "normal": 3 connections to 1 distinct destination (an upstream API).
		{"normal", "10.0.0.9"},
		{"normal", "10.0.0.9"},
		{"normal", "10.0.0.9"},
	}

	stats := aggregateEgress(conns, idForName)
	if len(stats) != 2 {
		t.Fatalf("len(stats) = %d, want 2 (%+v)", len(stats), stats)
	}
	// Sorted by name: crawler before normal.
	if stats[0].ContainerName != "crawler" || stats[1].ContainerName != "normal" {
		t.Errorf("not sorted by name: %+v", stats)
	}

	c, _ := statByName(stats, "crawler")
	if c.DistinctDestinations != 4 {
		t.Errorf("crawler distinct destinations = %d, want 4", c.DistinctDestinations)
	}
	if c.EgressConnections != 5 {
		t.Errorf("crawler egress connections = %d, want 5", c.EgressConnections)
	}
	if c.ContainerID != "uuid-c" {
		t.Errorf("crawler container id = %q, want uuid-c", c.ContainerID)
	}

	n, _ := statByName(stats, "normal")
	if n.DistinctDestinations != 1 {
		t.Errorf("normal distinct destinations = %d, want 1 (fan-out signal separates it from the crawler)", n.DistinctDestinations)
	}
	if n.EgressConnections != 3 {
		t.Errorf("normal egress connections = %d, want 3", n.EgressConnections)
	}
}

func TestAggregateEgress_EmptyAndNilID(t *testing.T) {
	if got := aggregateEgress(nil, nil); got == nil || len(got) != 0 {
		t.Errorf("aggregateEgress(nil,nil) = %+v, want empty non-nil slice", got)
	}
	// nil idForName must not panic and leaves ContainerID empty (standalone box).
	stats := aggregateEgress([]egressConn{{"solo", "8.8.8.8"}}, nil)
	if len(stats) != 1 || stats[0].ContainerID != "" || stats[0].DistinctDestinations != 1 {
		t.Fatalf("stats = %+v, want one solo @ 1 distinct, empty id", stats)
	}
}

func TestAggregateEgress_BlankDestIPNotCountedAsDistinct(t *testing.T) {
	// A connection with no resolved dst IP still counts toward connection total
	// but must not inflate the distinct-destination fan-out signal.
	stats := aggregateEgress([]egressConn{
		{"x", ""},
		{"x", "9.9.9.9"},
	}, nil)
	s, _ := statByName(stats, "x")
	if s.EgressConnections != 2 {
		t.Errorf("connections = %d, want 2", s.EgressConnections)
	}
	if s.DistinctDestinations != 1 {
		t.Errorf("distinct destinations = %d, want 1 (blank dst ignored)", s.DistinctDestinations)
	}
}
