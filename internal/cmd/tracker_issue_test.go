package cmd

import (
	"strings"
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestParseTrackerIssueListState(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    pb.TrackerIssueState
		wantErr bool
	}{
		{"empty matches any", "", pb.TrackerIssueState_TRACKER_ISSUE_STATE_UNSPECIFIED, false},
		{"open", "open", pb.TrackerIssueState_TRACKER_ISSUE_STATE_OPEN, false},
		{"closed", "closed", pb.TrackerIssueState_TRACKER_ISSUE_STATE_CLOSED, false},
		{"uppercase", "OPEN", pb.TrackerIssueState_TRACKER_ISSUE_STATE_OPEN, false},
		{"invalid", "merged", pb.TrackerIssueState_TRACKER_ISSUE_STATE_UNSPECIFIED, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseTrackerIssueListState(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil (result %v)", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("parseTrackerIssueListState(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestParseTrackerIssueNumber(t *testing.T) {
	if got, err := parseTrackerIssueNumber("42"); err != nil || got != 42 {
		t.Errorf("parseTrackerIssueNumber(42) = %d, %v, want 42, nil", got, err)
	}
	if _, err := parseTrackerIssueNumber("not-a-number"); err == nil {
		t.Error("parseTrackerIssueNumber(not-a-number) = nil error, want an error")
	}
}

func TestTrackerIssueStateLabel(t *testing.T) {
	tests := []struct {
		in   pb.TrackerIssueState
		want string
	}{
		{pb.TrackerIssueState_TRACKER_ISSUE_STATE_OPEN, "open"},
		{pb.TrackerIssueState_TRACKER_ISSUE_STATE_CLOSED, "closed"},
		{pb.TrackerIssueState_TRACKER_ISSUE_STATE_MERGED, "merged"},
		{pb.TrackerIssueState_TRACKER_ISSUE_STATE_UNSPECIFIED, "unspecified"},
	}
	for _, tt := range tests {
		if got := trackerIssueStateLabel(tt.in); got != tt.want {
			t.Errorf("trackerIssueStateLabel(%v) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestTrackerCiVerdictLabel(t *testing.T) {
	tests := []struct {
		in   pb.TrackerCiVerdict
		want string
	}{
		{pb.TrackerCiVerdict_TRACKER_CI_VERDICT_NONE, "none"},
		{pb.TrackerCiVerdict_TRACKER_CI_VERDICT_PENDING, "pending"},
		{pb.TrackerCiVerdict_TRACKER_CI_VERDICT_SUCCESS, "success"},
		{pb.TrackerCiVerdict_TRACKER_CI_VERDICT_FAILED, "failed"},
		{pb.TrackerCiVerdict_TRACKER_CI_VERDICT_UNSPECIFIED, "unspecified"},
	}
	for _, tt := range tests {
		if got := trackerCiVerdictLabel(tt.in); got != tt.want {
			t.Errorf("trackerCiVerdictLabel(%v) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestPrintTrackerIssue_UnassignedShowsPlaceholder(t *testing.T) {
	out := captureStdout(t, func() {
		printTrackerIssue(&pb.TrackerIssue{
			Number: 7, Title: "bug", State: pb.TrackerIssueState_TRACKER_ISSUE_STATE_OPEN,
		})
	})
	if !strings.Contains(out, "#7 bug") {
		t.Errorf("output = %q, want the number and title", out)
	}
	if !strings.Contains(out, "(unassigned)") {
		t.Errorf("output = %q, want an unassigned placeholder", out)
	}
}

func TestPrintTrackerIssue_WithCommentsAndLabels(t *testing.T) {
	out := captureStdout(t, func() {
		printTrackerIssue(&pb.TrackerIssue{
			Number: 8, Title: "feature", State: pb.TrackerIssueState_TRACKER_ISSUE_STATE_CLOSED,
			Assignee: "alice", Labels: []string{"bug", "p1"}, Body: "the body text",
			Comments: []*pb.TrackerComment{
				{Author: "bob", Body: "lgtm", CreatedAt: timestamppb.Now()},
			},
		})
	})
	if !strings.Contains(out, "assignee: alice") {
		t.Errorf("output = %q, want assignee: alice", out)
	}
	if !strings.Contains(out, "labels:   bug, p1") {
		t.Errorf("output = %q, want the joined labels", out)
	}
	if !strings.Contains(out, "the body text") {
		t.Errorf("output = %q, want the issue body", out)
	}
	if !strings.Contains(out, "1 comment(s)") || !strings.Contains(out, "bob") || !strings.Contains(out, "lgtm") {
		t.Errorf("output = %q, want the comment rendered", out)
	}
}
