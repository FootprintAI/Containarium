package runlog

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

type windowTailer struct {
	windows []*pb.TailRunLogResponse
	reqs    []*pb.TailRunLogRequest
}

func (w *windowTailer) TailRunLog(req *pb.TailRunLogRequest) (*pb.TailRunLogResponse, error) {
	w.reqs = append(w.reqs, req)
	r := w.windows[0]
	w.windows = w.windows[1:]
	return r, nil
}

func at(sec int) *timestamppb.Timestamp {
	return timestamppb.New(time.Date(2026, 10, 23, 0, 0, sec, 0, time.UTC))
}

func line(sec int, text string) string {
	return fmt.Sprintf(`{"t":"2026-10-23T00:00:0%d.000Z","kind":"status","text":"%s"}`+"\n", sec, text)
}

func call(sec int, status int32) *pb.GatewayCall {
	return &pb.GatewayCall{Time: at(sec), Provider: "anthropic", Status: status, KeyOwner: pb.GatewayKeyOwner_GATEWAY_KEY_OWNER_OPERATOR_FALLBACK}
}

func TestCopy_PlacesGatewayCallsByTimeAndNeverInsideALine(t *testing.T) {
	l1, l2, l3 := line(1, "a"), line(3, "b"), line(5, "c")
	// Window 1 ends in the middle of l2; the call at t=2 belongs between l1 and l2,
	// the one at t=4 between l2 and l3, the one at t=9 after everything.
	cut := len(l2) / 2
	w1 := &pb.TailRunLogResponse{Chunk: []byte(l1 + l2[:cut]), EndOffset: int64(len(l1) + cut), Truncated: true,
		GatewayCalls: []*pb.GatewayCall{call(2, 401)}, GatewayNextSeq: 1}
	w2 := &pb.TailRunLogResponse{Chunk: []byte(l2[cut:] + l3), EndOffset: int64(len(l1 + l2 + l3)), Ended: true,
		GatewayCalls: []*pb.GatewayCall{call(4, 429), call(9, 500)}, GatewayNextSeq: 3}
	tl := &windowTailer{windows: []*pb.TailRunLogResponse{w1, w2}}

	var out bytes.Buffer
	end, err := Copy(context.Background(), tl, &pb.TailRunLogRequest{RunId: "r"}, &out, false)
	if err != nil {
		t.Fatal(err)
	}
	if end != int64(len(l1+l2+l3)) {
		t.Errorf("end = %d", end)
	}
	lines := strings.Split(strings.TrimRight(out.String(), "\n"), "\n")
	var kinds []string
	for _, ln := range lines {
		switch {
		case strings.Contains(ln, `"kind":"gateway_call"`):
			kinds = append(kinds, "G")
		case strings.Contains(ln, `"text":"a"`):
			kinds = append(kinds, "a")
		case strings.Contains(ln, `"text":"b"`):
			kinds = append(kinds, "b")
		case strings.Contains(ln, `"text":"c"`):
			kinds = append(kinds, "c")
		default:
			t.Fatalf("a line was split or corrupted: %q", ln)
		}
	}
	if got := strings.Join(kinds, ""); got != "aGbGcG" {
		t.Errorf("order = %s, want aGbGcG\n%s", got, out.String())
	}
	if tl.reqs[1].GatewayAfterSeq != 1 {
		t.Errorf("second call did not resume the call cursor: %d", tl.reqs[1].GatewayAfterSeq)
	}
}

func TestCopy_WithoutCallsIsByteForByteTheJournal(t *testing.T) {
	body := line(1, "a") + line(2, "b")
	tl := &windowTailer{windows: []*pb.TailRunLogResponse{{Chunk: []byte(body), EndOffset: int64(len(body)), Ended: true}}}
	var out bytes.Buffer
	if _, err := Copy(context.Background(), tl, &pb.TailRunLogRequest{RunId: "r"}, &out, false); err != nil {
		t.Fatal(err)
	}
	if out.String() != body {
		t.Errorf("output changed: %q", out.String())
	}
}

func TestDescribeGatewayCall(t *testing.T) {
	for _, tc := range []struct {
		c    *pb.GatewayCall
		want string
	}{
		{&pb.GatewayCall{Status: 401, Provider: "anthropic"}, "Model call refused: credential invalid (401)"},
		{&pb.GatewayCall{Status: 429, Provider: "anthropic"}, "Model call refused: rate limited (429)"},
		{&pb.GatewayCall{Status: 529, Provider: "anthropic"}, "Model call failed: anthropic returned an error (529)"},
		{&pb.GatewayCall{Status: 200}, "Model call ok (200)"},
		{&pb.GatewayCall{Provider: "openai", TransportError: pb.GatewayTransportError_GATEWAY_TRANSPORT_ERROR_NO_KEY}, "Model call refused: the gateway holds no key for openai"},
		{&pb.GatewayCall{Provider: "openai", TransportError: pb.GatewayTransportError_GATEWAY_TRANSPORT_ERROR_TIMEOUT}, "Model call failed: openai timed out"},
	} {
		if got := DescribeGatewayCall(tc.c); got != tc.want {
			t.Errorf("got %q, want %q", got, tc.want)
		}
	}
}
