package mcp

import (
	"encoding/json"
	"testing"
)

// TestListBackends_DecodesProtoJSONStringInts is the regression test for the
// list_backends decode bug: grpc-gateway's protojson serializes int64 as a
// QUOTED STRING, which the prior plain-int64 fields rejected ("cannot
// unmarshal string into int64"), failing the whole response. flexInt64 must
// accept the string form (and the number form, for mixed-fleet safety).
func TestListBackends_DecodesProtoJSONStringInts(t *testing.T) {
	// Exactly the shape a proto-first daemon emits: int64s as strings.
	wire := `{
	  "backends": [
	    {
	      "id": "tunnel-fts-13700k-gpu",
	      "type": "tunnel",
	      "healthy": true,
	      "uptimeSeconds": "123456",
	      "containerCount": 7,
	      "gpus": [{"vendor":"NVIDIA","modelName":"RTX 3090","vramBytes":"25769803776"}]
	    }
	  ]
	}`
	var resp ListBackendsResponse
	if err := json.Unmarshal([]byte(wire), &resp); err != nil {
		t.Fatalf("decode proto-JSON (string int64) failed: %v", err)
	}
	if len(resp.Backends) != 1 {
		t.Fatalf("got %d backends, want 1", len(resp.Backends))
	}
	b := resp.Backends[0]
	if b.UptimeSeconds != 123456 {
		t.Errorf("UptimeSeconds = %d, want 123456", b.UptimeSeconds)
	}
	if len(b.GPUs) != 1 || b.GPUs[0].VRAMBytes != 25769803776 {
		t.Errorf("VRAMBytes = %d, want 25769803776", b.GPUs[0].VRAMBytes)
	}
}

// TestListBackends_DecodesNumberInts ensures the number form still works
// (a daemon / hand-coded handler that emits bare numbers).
func TestListBackends_DecodesNumberInts(t *testing.T) {
	wire := `{"backends":[{"id":"local","type":"local","healthy":true,"uptimeSeconds":42,"gpus":[{"vramBytes":1024}]}]}`
	var resp ListBackendsResponse
	if err := json.Unmarshal([]byte(wire), &resp); err != nil {
		t.Fatalf("decode number int64 failed: %v", err)
	}
	if resp.Backends[0].UptimeSeconds != 42 {
		t.Errorf("UptimeSeconds = %d, want 42", resp.Backends[0].UptimeSeconds)
	}
	if resp.Backends[0].GPUs[0].VRAMBytes != 1024 {
		t.Errorf("VRAMBytes = %d, want 1024", resp.Backends[0].GPUs[0].VRAMBytes)
	}
}

// Live host load (cloud #966) rides the same response, with the same
// string-encoded int64s. A missing block must stay nil rather than decoding
// into a zero-valued struct — an agent reading "0 bytes used" as spare
// capacity on a host we simply couldn't measure is the failure this field
// exists to prevent.
func TestListBackends_DecodesHostLoad(t *testing.T) {
	wire := `{
	  "backends": [
	    {
	      "id": "tunnel-byoc",
	      "type": "tunnel",
	      "healthy": true,
	      "containerCount": 5,
	      "hostLoad": {
	        "cpuLoad1m": 6.5,
	        "cpuLoad5m": 5,
	        "cpuLoad15m": 4,
	        "cpuCores": 8,
	        "memoryUsedBytes": "25769803776",
	        "memoryTotalBytes": "34359738368",
	        "diskUsedBytes": "536870912000",
	        "diskTotalBytes": "1073741824000",
	        "sampledAt": "2026-07-25T10:30:00Z"
	      }
	    },
	    {"id": "local", "type": "local", "healthy": true}
	  ]
	}`
	var resp ListBackendsResponse
	if err := json.Unmarshal([]byte(wire), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Backends) != 2 {
		t.Fatalf("got %d backends, want 2", len(resp.Backends))
	}

	l := resp.Backends[0].HostLoad
	if l == nil {
		t.Fatal("hostLoad is nil for a backend that reported one")
	}
	if l.CPULoad1m != 6.5 || l.CPUCores != 8 {
		t.Errorf("cpu = %v over %d cores, want 6.5 over 8", l.CPULoad1m, l.CPUCores)
	}
	if l.MemoryUsedBytes != 25769803776 || l.MemoryTotalBytes != 34359738368 {
		t.Errorf("memory = %d/%d, want 25769803776/34359738368", l.MemoryUsedBytes, l.MemoryTotalBytes)
	}
	if l.DiskUsedBytes != 536870912000 || l.DiskTotalBytes != 1073741824000 {
		t.Errorf("disk = %d/%d, want 536870912000/1073741824000", l.DiskUsedBytes, l.DiskTotalBytes)
	}
	if l.SampledAt != "2026-07-25T10:30:00Z" {
		t.Errorf("SampledAt = %q", l.SampledAt)
	}

	if resp.Backends[1].HostLoad != nil {
		t.Error("hostLoad must stay nil (unknown) when the backend reported none, not decode to zeros")
	}
}

// TestFlexInt64_EmptyAndNull tolerates omitted/null values → 0.
func TestFlexInt64_EmptyAndNull(t *testing.T) {
	var v struct {
		N flexInt64 `json:"n"`
	}
	// null and "" exercise flexInt64.UnmarshalJSON → 0. (An absent key
	// isn't tested: encoding/json never calls UnmarshalJSON for it, so the
	// field keeps its prior value — standard behavior, not flexInt64's job.)
	for _, in := range []string{`{"n":null}`, `{"n":""}`} {
		v.N = 7
		if err := json.Unmarshal([]byte(in), &v); err != nil {
			t.Fatalf("decode %q: %v", in, err)
		}
		if v.N != 0 {
			t.Errorf("decode %q: N = %d, want 0", in, v.N)
		}
	}
}
