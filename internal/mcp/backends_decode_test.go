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
