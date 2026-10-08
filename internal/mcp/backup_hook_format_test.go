package mcp

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// #2405: create_backup's hook_format is a thin wrapper over the same
// CreateBackup REST body the CLI's --hook-format produces. The wire value
// is the enum's NAME, which is what protojson decodes at the gateway.
func TestHandleCreateBackup_HookFormat(t *testing.T) {
	for _, tc := range []struct {
		name    string
		arg     interface{}
		want    string // expected hook_format on the wire; "" = absent
		wantErr bool
	}{
		{name: "omitted stays omitted (daemon default: opaque)", arg: nil, want: ""},
		{name: "opaque", arg: "opaque", want: "HOOK_FORMAT_OPAQUE"},
		{name: "pg_custom", arg: "pg_custom", want: "HOOK_FORMAT_PG_CUSTOM"},
		{name: "unknown value is refused before any call", arg: "plain_sql", wantErr: true},
		{name: "the enum spelling is not accepted", arg: "HOOK_FORMAT_PG_CUSTOM", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var body map[string]interface{}
			called := false
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
				b, _ := io.ReadAll(r.Body)
				_ = json.Unmarshal(b, &body)
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"message":"backup created: x","record":{"id":"x"}}`))
			}))
			defer srv.Close()

			args := map[string]interface{}{"username": "alice", "hook": "/opt/backup/db-dump.sh"}
			if tc.arg != nil {
				args["hook_format"] = tc.arg
			}
			_, err := handleCreateBackup(NewClient(srv.URL, "t"), args)
			if tc.wantErr {
				if err == nil || !strings.Contains(err.Error(), "hook_format") {
					t.Fatalf("err = %v, want one naming hook_format", err)
				}
				if called {
					t.Error("an invalid hook_format must not reach the daemon")
				}
				return
			}
			if err != nil {
				t.Fatalf("handleCreateBackup: %v", err)
			}
			got, present := body["hook_format"]
			if tc.want == "" {
				if present {
					t.Errorf("hook_format = %v, want it omitted", got)
				}
				return
			}
			if got != tc.want {
				t.Errorf("hook_format = %v, want %q", got, tc.want)
			}
		})
	}
}
