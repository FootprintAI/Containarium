//go:build !containarium_client

package server

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/footprintai/containarium/internal/runhook"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// eventsRun is a running box run whose audit directory is a temp dir, so a
// test can lay down the feed the root-run sink would have written.
type eventsRun struct {
	s     *ContainerServer
	owner string
	run   string
	audit string
}

func startEventsRun(t *testing.T) *eventsRun {
	t.Helper()
	s, owner, run := startLongRun(t, "{{READY}}\nsleep 60")
	s.boxRunAuditDir = t.TempDir()
	return &eventsRun{s: s, owner: owner, run: run.GetRunName(), audit: s.boxRunAuditDir}
}

// feed writes n events for run as the sink does: one protojson line each,
// seq = line number, from first. It appends to any feed already there.
func (r *eventsRun) feed(t *testing.T, run string, first, n int) {
	t.Helper()
	path := runhook.EventsPathUnder(r.audit, run)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	for i := first; i < first+n; i++ {
		e := &pb.AgentCommandEvent{
			Kind: pb.AgentCommandEventKind_AGENT_COMMAND_EVENT_KIND_BLOCKED, RunName: run, RunId: "id",
			ToolUseId: "tool-" + run, Argv: []string{"cmd", string(rune('a' + i%26))}, Seq: uint64(i), // #nosec G115 -- a small test counter
		}
		b, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(e)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write(append(b, '\n')); err != nil {
			t.Fatal(err)
		}
	}
}

func (r *eventsRun) done(t *testing.T, run string) {
	t.Helper()
	if err := os.WriteFile(runhook.DonePath(runhook.EventsPathUnder(r.audit, run)), nil, 0o600); err != nil {
		t.Fatal(err)
	}
}

func (r *eventsRun) list(t *testing.T, after uint64, limit int32) *pb.ListRunCommandEventsResponse {
	t.Helper()
	resp, err := r.s.ListRunCommandEvents(tenantCtx(r.owner), &pb.ListRunCommandEventsRequest{
		Username: r.owner, RunName: r.run, AfterSeq: after, Limit: limit})
	if err != nil {
		t.Fatalf("ListRunCommandEvents(after=%d, limit=%d): %v", after, limit, err)
	}
	return resp
}

func seqs(resp *pb.ListRunCommandEventsResponse) []uint64 {
	var out []uint64
	for _, e := range resp.GetEvents() {
		if e.GetEvent().GetSeq() != e.GetSeq() {
			out = append(out, 0) // entry and event disagree
			continue
		}
		out = append(out, e.GetSeq())
	}
	return out
}

func TestListRunCommandEvents_ReadsInOrderAndNotEndedWhileRunning(t *testing.T) {
	r := startEventsRun(t)
	r.feed(t, r.run, 1, 3)
	resp := r.list(t, 0, 0)
	if got := seqs(resp); len(got) != 3 || got[0] != 1 || got[1] != 2 || got[2] != 3 {
		t.Fatalf("seqs = %v, want [1 2 3]", got)
	}
	if resp.GetEnded() {
		t.Error("ended = true on a feed the sink has not finished")
	}
	if e := resp.GetEvents()[0].GetEvent(); e.GetRunName() != r.run || e.GetKind() != pb.AgentCommandEventKind_AGENT_COMMAND_EVENT_KIND_BLOCKED || len(e.GetArgv()) != 2 {
		t.Errorf("event = %v", e)
	}
}

// afterSeq paging walks the feed with no duplicate and no gap, for page sizes
// that do and do not divide the feed.
func TestListRunCommandEvents_PagingHasNoDuplicatesOrGaps(t *testing.T) {
	for _, limit := range []int32{1, 3, 7, 10, 11, 500} {
		r := startEventsRun(t)
		r.feed(t, r.run, 1, 10)
		r.done(t, r.run)
		var got []uint64
		after := uint64(0)
		for pages := 0; ; pages++ {
			if pages > 20 {
				t.Fatalf("limit %d: paging did not end", limit)
			}
			resp := r.list(t, after, limit)
			if len(resp.GetEvents()) > int(limit) {
				t.Fatalf("limit %d: page of %d", limit, len(resp.GetEvents()))
			}
			got = append(got, seqs(resp)...)
			if n := len(resp.GetEvents()); n > 0 {
				after = resp.GetEvents()[n-1].GetSeq()
			}
			if resp.GetEnded() {
				break
			}
			if len(resp.GetEvents()) == 0 {
				t.Fatalf("limit %d: an empty page that is not the end", limit)
			}
		}
		if len(got) != 10 {
			t.Fatalf("limit %d: got %v, want 1..10", limit, got)
		}
		for i, s := range got {
			if s != uint64(i+1) {
				t.Fatalf("limit %d: got %v, want 1..10 with no gap or repeat", limit, got)
			}
		}
	}
}

// ended means the sink is done AND this page reaches the last event.
func TestListRunCommandEvents_EndedNeedsDoneMarkerAndLastPage(t *testing.T) {
	r := startEventsRun(t)
	r.feed(t, r.run, 1, 4)
	if r.list(t, 0, 0).GetEnded() {
		t.Error("ended without the sink's done marker")
	}
	r.done(t, r.run)
	if r.list(t, 0, 2).GetEnded() {
		t.Error("ended on a page with events still waiting")
	}
	if !r.list(t, 0, 4).GetEnded() || !r.list(t, 2, 0).GetEnded() {
		t.Error("not ended on the page that reaches the last event")
	}
	if resp := r.list(t, 4, 0); len(resp.GetEvents()) != 0 || !resp.GetEnded() {
		t.Errorf("past the end: %v, want empty and ended", resp)
	}
}

func TestListRunCommandEvents_NoFeedIsEmpty(t *testing.T) {
	r := startEventsRun(t)
	resp := r.list(t, 0, 0)
	if len(resp.GetEvents()) != 0 || resp.GetEnded() {
		t.Errorf("a running run with no feed: %v, want empty and not ended", resp)
	}
}

func TestListRunCommandEvents_LimitDefaultAndMax(t *testing.T) {
	r := startEventsRun(t)
	r.feed(t, r.run, 1, 520)
	r.done(t, r.run)
	if n := len(r.list(t, 0, 0).GetEvents()); n != 500 {
		t.Errorf("default page = %d, want 500", n)
	}
	if n := len(r.list(t, 0, 100000).GetEvents()); n != 500 {
		t.Errorf("page over the maximum = %d, want 500", n)
	}
	if resp := r.list(t, 500, 0); len(resp.GetEvents()) != 20 || !resp.GetEnded() {
		t.Errorf("last page = %d events ended=%v, want 20 and ended", len(resp.GetEvents()), resp.GetEnded())
	}
	if _, err := r.s.ListRunCommandEvents(tenantCtx(r.owner), &pb.ListRunCommandEventsRequest{Username: r.owner, RunName: r.run, Limit: -1}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("negative limit err = %v, want InvalidArgument", err)
	}
}

// Another run's events are never returned, whether the run is on the same box
// or named by someone else.
func TestListRunCommandEvents_OtherRunsEventsNotReturned(t *testing.T) {
	a := startEventsRun(t)
	other := "other-run"
	a.feed(t, a.run, 1, 2)
	a.feed(t, other, 1, 5)
	a.done(t, other)
	resp := a.list(t, 0, 0)
	if len(resp.GetEvents()) != 2 {
		t.Fatalf("got %d events, want only this run's 2", len(resp.GetEvents()))
	}
	for _, e := range resp.GetEvents() {
		if e.GetEvent().GetRunName() != a.run {
			t.Errorf("event of run %q returned for %q", e.GetEvent().GetRunName(), a.run)
		}
	}
	if resp.GetEnded() {
		t.Error("another run's done marker ended this run's feed")
	}
	// A run that has a feed file but no record on this box is not found.
	_, err := a.s.ListRunCommandEvents(tenantCtx(a.owner), &pb.ListRunCommandEventsRequest{Username: a.owner, RunName: other})
	if status.Code(err) != codes.NotFound {
		t.Errorf("run without a record: err = %v, want NotFound", err)
	}
}

// A feed that holds another run's event, or has a gap, is refused: an audit
// path never returns what it cannot vouch for.
func TestListRunCommandEvents_RefusesAForeignOrGappedFeed(t *testing.T) {
	r := startEventsRun(t)
	r.feed(t, "someone-else", 1, 1)
	path := runhook.EventsPathUnder(r.audit, r.run)
	b, _ := os.ReadFile(runhook.EventsPathUnder(r.audit, "someone-else"))
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := r.s.ListRunCommandEvents(tenantCtx(r.owner), &pb.ListRunCommandEventsRequest{Username: r.owner, RunName: r.run}); status.Code(err) != codes.Internal {
		t.Errorf("foreign event: err = %v, want Internal", err)
	}

	g := startEventsRun(t)
	g.feed(t, g.run, 1, 1)
	g.feed(t, g.run, 3, 1) // seq 3 on line 2
	if _, err := g.s.ListRunCommandEvents(tenantCtx(g.owner), &pb.ListRunCommandEventsRequest{Username: g.owner, RunName: g.run}); status.Code(err) != codes.Internal {
		t.Errorf("gapped feed: err = %v, want Internal", err)
	}
}

func TestListRunCommandEvents_AccessAndValidation(t *testing.T) {
	r := startEventsRun(t)
	r.feed(t, r.run, 1, 1)
	if _, err := r.s.ListRunCommandEvents(tenantCtx("mallory"), &pb.ListRunCommandEventsRequest{Username: r.owner, RunName: r.run}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("another tenant: err = %v, want PermissionDenied", err)
	}
	for _, name := range []string{"", "../x", "a b", strings.Repeat("x", 300)} {
		if _, err := r.s.ListRunCommandEvents(tenantCtx(r.owner), &pb.ListRunCommandEventsRequest{Username: r.owner, RunName: name}); status.Code(err) != codes.InvalidArgument {
			t.Errorf("run %q: err = %v, want InvalidArgument", name, err)
		}
	}
	if _, err := r.s.ListRunCommandEvents(tenantCtx(r.owner), &pb.ListRunCommandEventsRequest{Username: r.owner, RunName: "nope"}); status.Code(err) != codes.NotFound {
		t.Errorf("no such run: err = %v, want NotFound", err)
	}
}

// The route only reads: the feed is byte-for-byte what it was.
func TestListRunCommandEvents_DoesNotModifyTheFeed(t *testing.T) {
	r := startEventsRun(t)
	r.feed(t, r.run, 1, 3)
	path := runhook.EventsPathUnder(r.audit, r.run)
	before, _ := os.ReadFile(path)
	r.list(t, 0, 0)
	r.list(t, 1, 1)
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Error("reading the feed changed it")
	}
}

// The REST body is the shape the control plane decodes: {"events":[{"seq":
// "<uint64 as a string>","event":{camelCase fields}}],"ended":bool}, with the
// gateway's marshaler options.
func TestListRunCommandEvents_RESTShape(t *testing.T) {
	r := startEventsRun(t)
	r.feed(t, r.run, 1, 1)
	resp := r.list(t, 0, 0)
	b, err := protojson.MarshalOptions{UseProtoNames: false, EmitUnpopulated: true}.Marshal(resp)
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Events []struct {
			Seq   string `json:"seq"`
			Event struct {
				Kind      string   `json:"kind"`
				RunName   string   `json:"runName"`
				ToolUseID string   `json:"toolUseId"`
				Argv      []string `json:"argv"`
				Seq       string   `json:"seq"`
			} `json:"event"`
		} `json:"events"`
		Ended *bool `json:"ended"`
	}
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("%v: %s", err, b)
	}
	if len(got.Events) != 1 || got.Ended == nil || got.Events[0].Seq != "1" || got.Events[0].Event.Seq != "1" ||
		got.Events[0].Event.Kind != "AGENT_COMMAND_EVENT_KIND_BLOCKED" || got.Events[0].Event.ToolUseID != "tool-"+r.run || got.Events[0].Event.RunName != r.run {
		t.Errorf("body = %s", b)
	}
}
