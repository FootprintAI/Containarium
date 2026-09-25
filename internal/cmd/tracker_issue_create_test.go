package cmd

import (
	"testing"
	"time"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// Table-driven flag validation for `tracker issue create` — the request
// builder is the seam the cobra RunE hands its flags to, so it's what
// gets tested (same convention as parseTrackerProvider / printTrackerStatus).
func TestBuildCreateTrackerIssueRequest(t *testing.T) {
	tests := []struct {
		name    string
		title   string
		body    string
		labels  []string
		parent  int64
		wantErr bool
	}{
		{"happy path", "Design the thing", "body", []string{"scope:architecture"}, 42, false},
		{"no parent is fine for the builder (daemon decides per token)", "t", "", nil, 0, false},
		{"labels are trimmed", "t", "", []string{"  scope:architecture "}, 1, false},
		{"empty title", "", "body", nil, 1, true},
		{"whitespace-only title", "   ", "body", nil, 1, true},
		{"negative parent", "t", "", nil, -1, true},
		{"empty label", "t", "", []string{"scope:architecture", ""}, 1, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := buildCreateTrackerIssueRequest("alice", "default", tt.title, tt.body, tt.labels, tt.parent)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got request %+v", req)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if req.Username != "alice" || req.Connection != "default" || req.Title != tt.title || req.Body != tt.body || req.ParentNumber != tt.parent {
				t.Errorf("request = %+v, want the inputs carried through", req)
			}
			for _, l := range req.Labels {
				if l != "scope:architecture" {
					t.Errorf("labels = %v, want trimmed scope:architecture", req.Labels)
				}
			}
		})
	}
}

func TestBuildTrackerPolicy(t *testing.T) {
	tests := []struct {
		name        string
		allow       []string
		autoChain   bool
		maxDepth    int32
		maxChildren int32
		runTimeout  time.Duration
		want        *pb.TrackerPolicy
		wantErr     bool
	}{
		{
			name: "all zero means daemon defaults",
			want: &pb.TrackerPolicy{},
		},
		{
			name: "explicit values", allow: []string{"scope:*", "triaged"}, autoChain: true,
			maxDepth: 2, maxChildren: 4, runTimeout: 90 * time.Second,
			want: &pb.TrackerPolicy{LabelAllowList: []string{"scope:*", "triaged"}, AutoChain: true, MaxDepth: 2, MaxChildrenPerRun: 4, RunTimeoutSeconds: 90},
		},
		{name: "negative max-depth", maxDepth: -1, wantErr: true},
		{name: "negative max-children", maxChildren: -1, wantErr: true},
		{name: "negative run-timeout", runTimeout: -time.Second, wantErr: true},
		{name: "empty allow entry", allow: []string{"scope:*", " "}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := buildTrackerPolicy(tt.allow, tt.autoChain, tt.maxDepth, tt.maxChildren, tt.runTimeout)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %+v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.GetAutoChain() != tt.want.GetAutoChain() || got.GetMaxDepth() != tt.want.GetMaxDepth() ||
				got.GetMaxChildrenPerRun() != tt.want.GetMaxChildrenPerRun() || got.GetRunTimeoutSeconds() != tt.want.GetRunTimeoutSeconds() {
				t.Errorf("policy = %+v, want %+v", got, tt.want)
			}
			if len(got.GetLabelAllowList()) != len(tt.want.GetLabelAllowList()) {
				t.Errorf("allow list = %v, want %v", got.GetLabelAllowList(), tt.want.GetLabelAllowList())
			}
		})
	}
}
