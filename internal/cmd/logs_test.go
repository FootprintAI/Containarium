package cmd

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/footprintai/containarium/internal/boxlogs"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// fakeLogsServer answers TailBoxLogs with canned windows and records each
// request.
type fakeLogsServer struct {
	windows []*pb.TailBoxLogsResponse
	reqs    []*pb.TailBoxLogsRequest
}

func (f *fakeLogsServer) TailBoxLogs(req *pb.TailBoxLogsRequest) (*pb.TailBoxLogsResponse, error) {
	f.reqs = append(f.reqs, req)
	return f.windows[min(len(f.reqs), len(f.windows))-1], nil
}

// Flags become the TailBoxLogs request: --since as a duration back from now
// or a timestamp, --tail, and repeatable --unit / --container.
func TestLogsRequest(t *testing.T) {
	now := time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name    string
		opts    logsOptions
		want    *pb.TailBoxLogsRequest
		wantErr string
	}{
		{name: "defaults", want: &pb.TailBoxLogsRequest{Username: "alice"}},
		{name: "since duration", opts: logsOptions{since: "10m"}, want: &pb.TailBoxLogsRequest{Username: "alice", Since: timestamppb.New(now.Add(-10 * time.Minute))}},
		{name: "since timestamp", opts: logsOptions{since: "2026-11-11T11:30:00Z"}, want: &pb.TailBoxLogsRequest{Username: "alice", Since: timestamppb.New(now.Add(-30 * time.Minute))}},
		{name: "filters and tail", opts: logsOptions{tail: 20, units: []string{"nginx"}, containers: []string{"web", "db"}, maxLines: 50},
			want: &pb.TailBoxLogsRequest{Username: "alice", Tail: 20, Units: []string{"nginx"}, Containers: []string{"web", "db"}, MaxLines: 50}},
		{name: "bad since", opts: logsOptions{since: "yesterday"}, wantErr: "--since"},
		{name: "negative since", opts: logsOptions{since: "-5m"}, wantErr: "--since"},
		{name: "negative tail", opts: logsOptions{tail: -1}, wantErr: "--tail"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := logsRequest("alice", tc.opts, now)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want one mentioning %s", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got.String() != tc.want.String() {
				t.Errorf("request = %v, want %v", got, tc.want)
			}
		})
	}
}

// `containarium logs` prints every window through the shared reader, resuming
// each one from the previous cursor.
func TestBoxLogs_PrintsWindows(t *testing.T) {
	line := func(sec int, kind pb.BoxLogSourceKind, src, text string) *pb.BoxLogLine {
		return &pb.BoxLogLine{Time: timestamppb.New(time.Date(2026, 11, 11, 12, 0, sec, 0, time.UTC)), SourceKind: kind, Source: src, Text: text}
	}
	f := &fakeLogsServer{windows: []*pb.TailBoxLogsResponse{
		{Status: pb.BoxLogsStatus_BOX_LOGS_STATUS_OK, Cursor: "c1", More: true, Lines: []*pb.BoxLogLine{line(1, pb.BoxLogSourceKind_BOX_LOG_SOURCE_KIND_JOURNAL, "nginx.service", "up")}},
		{Status: pb.BoxLogsStatus_BOX_LOGS_STATUS_OK, Cursor: "c2", Lines: []*pb.BoxLogLine{line(2, pb.BoxLogSourceKind_BOX_LOG_SOURCE_KIND_CONTAINER, "web", "GET /")}},
	}}
	var out bytes.Buffer
	if err := boxLogs(context.Background(), f, &pb.TailBoxLogsRequest{Username: "alice", Tail: 5}, false, &out); err != nil {
		t.Fatal(err)
	}
	want := "2026-11-11T12:00:01Z journal/nginx.service up\n2026-11-11T12:00:02Z container/web GET /\n"
	if out.String() != want {
		t.Errorf("output =\n%s\nwant\n%s", out.String(), want)
	}
	if len(f.reqs) != 2 || f.reqs[1].GetCursor() != "c1" {
		t.Errorf("requests = %v", f.reqs)
	}
}

// A stopped box is an error that says so, and nothing is printed.
func TestBoxLogs_StoppedBox(t *testing.T) {
	f := &fakeLogsServer{windows: []*pb.TailBoxLogsResponse{{Status: pb.BoxLogsStatus_BOX_LOGS_STATUS_BOX_STOPPED, Reason: "the box is not running"}}}
	var out bytes.Buffer
	err := boxLogs(context.Background(), f, &pb.TailBoxLogsRequest{Username: "alice"}, false, &out)
	var se *boxlogs.StatusError
	if !errors.As(err, &se) || !strings.Contains(err.Error(), "stopped") || out.Len() != 0 {
		t.Fatalf("err = %v, output %q", err, out.String())
	}
}

func TestLogsCommandRegistered(t *testing.T) {
	c, _, err := rootCmd.Find([]string{"logs"})
	if err != nil || c.Name() != "logs" {
		t.Fatalf("containarium logs not registered: %v", err)
	}
	for _, f := range []string{"since", "tail", "unit", "container", "follow", "max-lines"} {
		if c.Flags().Lookup(f) == nil {
			t.Errorf("logs has no --%s", f)
		}
	}
}
