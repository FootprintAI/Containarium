package mcp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// #3709: query_flow_history is a thin wrapper over the REST call
// `containarium security flow-history` makes.

func TestQueryFlowHistoryTool_ForwardsAndRenders(t *testing.T) {
	var gotPath string
	var gotQuery map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotQuery = map[string]string{}
		for k := range r.URL.Query() {
			gotQuery[k] = r.URL.Query().Get(k)
		}
		_, _ = w.Write([]byte(`{"entries":[{"container":"box-a","tenantId":"org","srcIp":"10.0.3.2","dstIp":"91.121.106.55",` +
			`"dstPort":4444,"protocol":"tcp","firstSeen":"2026-11-13T16:30:00Z","lastSeen":"2026-11-13T16:36:00Z","bytes":"300","packets":"3"}],` +
			`"coveredSince":"2026-11-13T12:00:00Z","retentionSeconds":"7200","someFutureField":1}`))
	}))
	defer srv.Close()

	out, err := handleQueryFlowHistory(NewClient(srv.URL, "tok"), map[string]interface{}{
		"dst_ip": " 91.121.106.55 ", "dst_port": float64(4444), "since": "2026-11-13T16:00:00Z", "tenant": "org", "limit": float64(10),
	})
	if err != nil {
		t.Fatalf("handleQueryFlowHistory: %v", err)
	}
	if gotPath != "/v1/security/flow-history" {
		t.Errorf("path = %q", gotPath)
	}
	for k, want := range map[string]string{"dst_ip": "91.121.106.55", "dst_port": "4444", "since": "2026-11-13T16:00:00Z", "tenant_id": "org", "limit": "10"} {
		if gotQuery[k] != want {
			t.Errorf("query %s = %q, want %q", k, gotQuery[k], want)
		}
	}
	if _, sent := gotQuery["until"]; sent {
		t.Error("an unset until must not be sent")
	}
	// The result names the box and, always, what the log covers.
	for _, want := range []string{"box-a", "91.121.106.55", "coveredSince", "retentionSeconds"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

// A daemon with the log off answers with an error; it must reach the caller as
// one, not as an empty result.
func TestQueryFlowHistoryTool_DisabledLogIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusPreconditionFailed)
		_, _ = w.Write([]byte(`{"code":9,"message":"the flow log is not enabled"}`))
	}))
	defer srv.Close()
	_, err := handleQueryFlowHistory(NewClient(srv.URL, "tok"), map[string]interface{}{"dst_ip": "91.121.106.55"})
	if err == nil || !strings.Contains(err.Error(), "query flow history") {
		t.Fatalf("err = %v, want a wrapped query error", err)
	}
}

func TestQueryFlowHistoryTool_RejectsBadInputBeforeAnyRequest(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	defer srv.Close()
	for name, args := range map[string]map[string]interface{}{
		"missing":      {},
		"hostname":     {"dst_ip": "pool.example.com"},
		"ipv6":         {"dst_ip": "2001:db8::1"},
		"port too big": {"dst_ip": "91.121.106.55", "dst_port": float64(70000)},
		"negative":     {"dst_ip": "91.121.106.55", "dst_port": float64(-1)},
	} {
		if _, err := handleQueryFlowHistory(NewClient(srv.URL, "tok"), args); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
	if called {
		t.Error("invalid input must be rejected before any request is made")
	}
}
