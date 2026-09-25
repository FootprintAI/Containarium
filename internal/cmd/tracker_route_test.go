package cmd

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// `containarium tracker route set|list|delete` (#2021).

func TestBuildSetTrackerRouteRequest_FlagValidation(t *testing.T) {
	tests := []struct {
		name    string
		scope   string
		skill   string
		want    *pb.SetTrackerRouteRequest
		wantErr string
	}{
		{
			name: "valid", scope: "product", skill: "product-define",
			want: &pb.SetTrackerRouteRequest{Username: "alice", Connection: "default", Scope: "product", SkillId: "product-define"},
		},
		{
			name: "surrounding whitespace trimmed", scope: "  product ", skill: " product-define ",
			want: &pb.SetTrackerRouteRequest{Username: "alice", Connection: "default", Scope: "product", SkillId: "product-define"},
		},
		{name: "missing --scope", scope: "", skill: "product-define", wantErr: "--scope is required"},
		{name: "missing --skill", scope: "product", skill: "", wantErr: "--skill is required"},
		{name: "full label instead of suffix", scope: "scope:product", skill: "product-define", wantErr: `--scope product`},
		{name: "invalid characters", scope: "has space", skill: "product-define", wantErr: "scope"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := buildSetTrackerRouteRequest("alice", "default", tt.scope, tt.skill)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want one containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.Username != tt.want.Username || got.Connection != tt.want.Connection || got.Scope != tt.want.Scope || got.SkillId != tt.want.SkillId {
				t.Errorf("request = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestBuildDeleteTrackerRouteRequest_FlagValidation(t *testing.T) {
	if _, err := buildDeleteTrackerRouteRequest("alice", "default", ""); err == nil || !strings.Contains(err.Error(), "--scope is required") {
		t.Fatalf("empty --scope err = %v, want --scope is required", err)
	}
	if _, err := buildDeleteTrackerRouteRequest("alice", "default", "scope:qa"); err == nil {
		t.Fatal("prefixed --scope err = nil, want an error")
	}
	got, err := buildDeleteTrackerRouteRequest("alice", "default", "qa")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Username != "alice" || got.Connection != "default" || got.Scope != "qa" {
		t.Errorf("request = %+v", got)
	}
}

func TestPrintTrackerRoutes(t *testing.T) {
	empty := captureStdout(t, func() { printTrackerRoutes("alice", "default", nil) })
	if !strings.Contains(empty, "no scope routes") {
		t.Errorf("empty output = %q, want a no-routes placeholder", empty)
	}
	out := captureStdout(t, func() {
		printTrackerRoutes("alice", "default", []*pb.TrackerRoute{
			{Username: "alice", Connection: "default", Scope: "product", SkillId: "product-define"},
		})
	})
	if !strings.Contains(out, "scope:product") || !strings.Contains(out, "product-define") {
		t.Errorf("output = %q, want the label and skill", out)
	}
}

// TestTrackerRouteSet_HTTPModeHitsGatewayPath drives the real cobra
// handler in --http mode against a stub gateway, proving the CLI and the
// REST mapping in tracker.proto agree on method and path.
func TestTrackerRouteSet_HTTPModeHitsGatewayPath(t *testing.T) {
	var gotMethod, gotPath, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.Path
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"message":"route created","route":{"username":"alice","connection":"default","scope":"product","skillId":"product-define"}}`)
	}))
	defer srv.Close()

	oldServer, oldHTTP, oldToken := serverAddr, httpMode, authToken
	oldScope, oldSkill := trackerRouteScope, trackerRouteSkill
	t.Cleanup(func() {
		serverAddr, httpMode, authToken = oldServer, oldHTTP, oldToken
		trackerRouteScope, trackerRouteSkill = oldScope, oldSkill
	})
	serverAddr, httpMode, authToken = srv.URL, true, "tok"
	trackerRouteScope, trackerRouteSkill = "product", "product-define"

	out := captureStdout(t, func() {
		if err := runTrackerRouteSet(trackerRouteSetCmd, []string{"alice", "default"}); err != nil {
			t.Errorf("runTrackerRouteSet: %v", err)
		}
	})
	if gotMethod != http.MethodPut {
		t.Errorf("method = %q, want PUT", gotMethod)
	}
	if gotPath != "/v1/tracker/alice/default/routes/product" {
		t.Errorf("path = %q, want /v1/tracker/alice/default/routes/product", gotPath)
	}
	if !strings.Contains(gotBody, `"skillId":"product-define"`) {
		t.Errorf("body = %s, want skillId", gotBody)
	}
	if !strings.Contains(out, "route created") {
		t.Errorf("output = %q, want the server message", out)
	}
}
