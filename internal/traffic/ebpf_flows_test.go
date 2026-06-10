package traffic

import (
	"testing"
	"time"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// newTestCollector builds a Collector with no conntrack monitor or incus client,
// suitable for exercising the eBPF flow merge path in isolation. The cache is
// seeded non-empty so GetConnections skips its incus-backed Refresh.
func newTestCollector() *Collector {
	cache := NewContainerCache(nil, "10.100.0.0/24")
	cache.nameToIP["seed-container"] = "10.100.0.1" // make Size() > 0
	return &Collector{
		cache:       cache,
		connections: make(map[string]*pb.Connection),
		ebpfFlows:   make(map[string]*pb.Connection),
	}
}

func TestIngestEBPFFlows_SurfacesInGetConnections(t *testing.T) {
	c := newTestCollector()

	now := time.Now()
	c.IngestEBPFFlows([]EBPFFlow{
		{
			ContainerName: "web-container",
			ContainerIP:   "10.100.0.42",
			Protocol:      "tcp",
			SrcIP:         "10.100.0.42",
			SrcPort:       51000,
			DstIP:         "1.1.1.1",
			DstPort:       443,
			Bytes:         8456,
			Packets:       12,
			RxBytes:       12_004,
			RxPackets:     9,
			First:         now.Add(-2 * time.Second),
			Last:          now,
		},
		{
			ContainerName: "db-container",
			ContainerIP:   "10.100.0.43",
			Protocol:      "udp",
			SrcIP:         "10.100.0.43",
			SrcPort:       33000,
			DstIP:         "8.8.8.8",
			DstPort:       53,
			Bytes:         120,
			Packets:       2,
			First:         now,
			Last:          now,
		},
	})

	// Filtered by container.
	web := c.GetConnections("web-container")
	if len(web) != 1 {
		t.Fatalf("GetConnections(web-container) = %d conns, want 1", len(web))
	}
	got := web[0]
	if got.SourceIp != "10.100.0.42" || got.DestIp != "1.1.1.1" || got.DestPort != 443 {
		t.Errorf("unexpected 5-tuple: src=%s dst=%s:%d", got.SourceIp, got.DestIp, got.DestPort)
	}
	if got.BytesSent != 8456 || got.PacketsSent != 12 {
		t.Errorf("byte/packet counts = %d/%d, want 8456/12", got.BytesSent, got.PacketsSent)
	}
	if got.BytesReceived != 12_004 || got.PacketsReceived != 9 {
		t.Errorf("rx byte/packet = %d/%d, want 12004/9 (#631)", got.BytesReceived, got.PacketsReceived)
	}
	if got.Direction != pb.TrafficDirection_TRAFFIC_DIRECTION_EGRESS {
		t.Errorf("direction = %v, want EGRESS", got.Direction)
	}
	if got.Protocol != pb.Protocol_PROTOCOL_TCP {
		t.Errorf("protocol = %v, want TCP", got.Protocol)
	}

	// Unfiltered returns both eBPF flows.
	if all := c.GetConnections(""); len(all) != 2 {
		t.Fatalf("GetConnections(\"\") = %d conns, want 2", len(all))
	}
}

func TestIngestEBPFFlows_ReplacesSnapshot(t *testing.T) {
	c := newTestCollector()
	c.IngestEBPFFlows([]EBPFFlow{{ContainerName: "web-container", SrcIP: "10.100.0.42", DstIP: "1.1.1.1", Protocol: "tcp", Bytes: 1}})
	if n := len(c.GetConnections("")); n != 1 {
		t.Fatalf("after first ingest = %d, want 1", n)
	}
	// A fresh snapshot with a different flow set fully replaces the prior one
	// (flows the LRU map evicted must not linger).
	c.IngestEBPFFlows([]EBPFFlow{{ContainerName: "db-container", SrcIP: "10.100.0.43", DstIP: "8.8.8.8", Protocol: "udp", Bytes: 2}})
	got := c.GetConnections("")
	if len(got) != 1 {
		t.Fatalf("after replace = %d, want 1", len(got))
	}
	if got[0].ContainerName != "db-container" {
		t.Errorf("stale flow lingered: got %s", got[0].ContainerName)
	}
}

func TestIngestEBPFFlows_EmptyClears(t *testing.T) {
	c := newTestCollector()
	c.IngestEBPFFlows([]EBPFFlow{{ContainerName: "web-container", SrcIP: "10.100.0.42", DstIP: "1.1.1.1", Protocol: "tcp"}})
	c.IngestEBPFFlows(nil)
	if n := len(c.GetConnections("")); n != 0 {
		t.Errorf("after empty ingest = %d conns, want 0", n)
	}
}
