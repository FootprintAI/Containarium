package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/credentials"
	"github.com/spf13/cobra"
)

func TestFlexInt64_UnmarshalsQuotedAndBare(t *testing.T) {
	// grpc-gateway (proto3 JSON) emits int64 as a quoted string; tolerate both.
	var s struct {
		A flexInt64 `json:"a"`
		B flexInt64 `json:"b"`
		C flexInt64 `json:"c"`
	}
	if err := json.Unmarshal([]byte(`{"a":"8456","b":42,"c":""}`), &s); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if s.A != 8456 || s.B != 42 || s.C != 0 {
		t.Errorf("got a=%d b=%d c=%d, want 8456/42/0", s.A, s.B, s.C)
	}
}

func TestProtocolEnum(t *testing.T) {
	cases := map[string]string{"": "", "tcp": "PROTOCOL_TCP", "UDP": "PROTOCOL_UDP", "icmp": "PROTOCOL_ICMP"}
	for in, want := range cases {
		got, err := protocolEnum(in)
		if err != nil || got != want {
			t.Errorf("protocolEnum(%q) = (%q, %v), want %q", in, got, err, want)
		}
	}
	if _, err := protocolEnum("sctp"); err == nil {
		t.Error("expected error for unknown protocol")
	}
}

func TestShortEnum(t *testing.T) {
	cases := map[string]string{
		"PROTOCOL_TCP":                 "tcp",
		"TRAFFIC_DIRECTION_EGRESS":     "egress",
		"CONNECTION_STATE_ESTABLISHED": "established",
		"PROTOCOL_UNSPECIFIED":         "-",
		"":                             "-",
	}
	for in, want := range cases {
		if got := shortEnum(in); got != want {
			t.Errorf("shortEnum(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestHostPort(t *testing.T) {
	cases := []struct {
		ip   string
		port uint32
		want string
	}{
		{"1.1.1.1", 443, "1.1.1.1:443"},
		{"10.0.0.5", 0, "10.0.0.5"}, // ICMP / unset port
		{"", 80, "-"},
	}
	for _, c := range cases {
		if got := hostPort(c.ip, c.port); got != c.want {
			t.Errorf("hostPort(%q,%d) = %q, want %q", c.ip, c.port, got, c.want)
		}
	}
}

// TestTrafficConnections_EndToEnd drives runTrafficConnections against a stub
// daemon: it must hit the right path with the bearer token + filters, decode
// the quoted-int64 bytes, and render a table.
func TestTrafficConnections_EndToEnd(t *testing.T) {
	home := withTempHome(t)

	var gotPath, gotQuery, gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotQuery = r.URL.RawQuery
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"connections":[{"containerName":"web-container",` +
			`"protocol":"PROTOCOL_TCP","sourceIp":"10.100.0.42","sourcePort":51000,` +
			`"destIp":"1.1.1.1","destPort":443,"direction":"TRAFFIC_DIRECTION_EGRESS",` +
			`"state":"CONNECTION_STATE_ESTABLISHED","bytesSent":"8456","bytesReceived":"0"}],` +
			`"totalCount":1}`))
	}))
	defer srv.Close()

	// Log in to the stub so pickSSHServer + resolveAuthToken resolve to it.
	_ = seedCreds(t, home, srv.URL, map[string]credentials.ServerCreds{
		srv.URL: {Token: "tok-traffic"},
	})

	trafficServerFlag, trafficFormat, trafficProtocol = "", "table", "tcp"
	trafficDestIP, trafficDestPort, trafficLimit = "", 0, 0
	t.Cleanup(func() { trafficServerFlag, trafficFormat, trafficProtocol = "", "table", "" })

	var buf bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&buf)
	cmd.SetContext(context.Background())
	if err := runTrafficConnections(cmd, []string{"web-container"}); err != nil {
		t.Fatalf("runTrafficConnections: %v", err)
	}

	if gotPath != "/v1/containers/web-container/connections" {
		t.Errorf("path = %q", gotPath)
	}
	if !strings.Contains(gotQuery, "protocol=PROTOCOL_TCP") {
		t.Errorf("query missing protocol filter: %q", gotQuery)
	}
	if gotAuth != "Bearer tok-traffic" {
		t.Errorf("auth = %q, want Bearer tok-traffic", gotAuth)
	}
	out := buf.String()
	for _, want := range []string{"tcp", "10.100.0.42:51000", "1.1.1.1:443", "egress", "established", "8.3 KiB"} {
		if !strings.Contains(out, want) {
			t.Errorf("table missing %q; got:\n%s", want, out)
		}
	}
}

// #2884: history exposes the destination filters and an absolute window; find
// is the host-wide form and names the box on every row.
func runTrafficStub(t *testing.T, body string, run func(*cobra.Command) error) (path, query, out string) {
	t.Helper()
	home := withTempHome(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path, query = r.URL.Path, r.URL.Query().Encode()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	_ = seedCreds(t, home, srv.URL, map[string]credentials.ServerCreds{srv.URL: {Token: "tok"}})
	trafficServerFlag, trafficFormat = "", "table"
	trafficDestIP, trafficDestPort, trafficLimit = "", 0, 0
	trafficSince, trafficFrom, trafficTo = time.Hour, "", ""
	var buf bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&buf)
	cmd.SetContext(context.Background())
	if err := run(cmd); err != nil {
		t.Fatalf("run: %v", err)
	}
	return path, query, buf.String()
}

func TestTrafficHistory_DestFilterAndAbsoluteWindow(t *testing.T) {
	path, query, _ := runTrafficStub(t, `{"connections":[],"totalCount":0}`, func(cmd *cobra.Command) error {
		trafficDestIP, trafficDestPort = "203.0.113.9", 3333
		trafficFrom, trafficTo = "2026-10-20T10:00:00Z", "2026-10-20T11:00:00Z"
		return runTrafficHistory(cmd, []string{"web-container"})
	})
	if path != "/v1/containers/web-container/traffic/history" {
		t.Errorf("path = %q", path)
	}
	for _, want := range []string{"destIp=203.0.113.9", "destPort=3333", "startTime=2026-10-20T10%3A00%3A00Z", "endTime=2026-10-20T11%3A00%3A00Z"} {
		if !strings.Contains(query, want) {
			t.Errorf("query %q missing %q", query, want)
		}
	}
}

func TestTrafficHistory_BadWindowIsRejected(t *testing.T) {
	for _, tc := range [][2]string{{"yesterday", ""}, {"2026-10-20T10:00:00Z", "nope"}, {"", "2026-10-20T10:00:00Z"}, {"2026-10-20T11:00:00Z", "2026-10-20T10:00:00Z"}} {
		trafficFrom, trafficTo, trafficSince = tc[0], tc[1], time.Hour
		if _, _, err := historyWindow(time.Now()); err == nil {
			t.Errorf("from=%q to=%q: want an error", tc[0], tc[1])
		}
	}
	trafficFrom, trafficTo = "", ""
}

func TestTrafficFind_NamesTheBoxOnEveryRow(t *testing.T) {
	path, query, out := runTrafficStub(t,
		`{"connections":[{"containerName":"alice-container","protocol":"PROTOCOL_TCP","sourceIp":"10.0.0.2","sourcePort":40000,"destIp":"203.0.113.9","destPort":3333,"bytesSent":"10","bytesReceived":"0","startedAt":"2026-10-20T10:30:00Z"}],"totalCount":1,"oldestRecordTime":"2026-10-19T00:00:00Z"}`,
		func(cmd *cobra.Command) error {
			trafficDestIP, trafficDestPort = "203.0.113.9", 3333
			trafficFrom, trafficTo = "2026-10-20T10:00:00Z", "2026-10-20T11:00:00Z"
			return runTrafficFind(cmd, nil)
		})
	if path != "/v1/traffic/history" {
		t.Errorf("path = %q, want the host-wide route", path)
	}
	if !strings.Contains(query, "destIp=203.0.113.9") || !strings.Contains(query, "startTime=") {
		t.Errorf("query = %q", query)
	}
	for _, want := range []string{"alice-container", "203.0.113.9:3333", "2026-10-20T10:30:00Z"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

func TestTrafficFind_EmptyResultSaysWhatIsHeld(t *testing.T) {
	_, _, out := runTrafficStub(t, `{"connections":[],"totalCount":0,"oldestRecordTime":"2026-10-19T00:00:00Z"}`, func(cmd *cobra.Command) error {
		trafficFrom = "2026-10-20T10:00:00Z"
		return runTrafficFind(cmd, nil)
	})
	if !strings.Contains(out, "2026-10-19T00:00:00Z") {
		t.Errorf("empty result must report the oldest record held:\n%s", out)
	}
	_, _, out = runTrafficStub(t, `{"connections":[],"totalCount":0}`, func(cmd *cobra.Command) error {
		trafficFrom = "2026-10-20T10:00:00Z"
		return runTrafficFind(cmd, nil)
	})
	if !strings.Contains(out, "no history is held") {
		t.Errorf("empty result with no records must say nothing is held:\n%s", out)
	}
}
