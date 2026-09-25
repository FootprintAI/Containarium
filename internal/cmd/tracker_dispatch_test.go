package cmd

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// `containarium tracker dispatch` / `tracker dispatches` (#2022).

func TestTrackerDispatch_OnceAndInterval(t *testing.T) {
	t.Run("--once returns after one tick with its error", func(t *testing.T) {
		calls := 0
		want := errors.New("tick failed")
		err := runDispatchLoop(context.Background(), true, time.Hour, func() error { calls++; return want }, func(string, ...any) {})
		if calls != 1 || !errors.Is(err, want) {
			t.Fatalf("calls = %d, err = %v; want 1 call returning the tick error", calls, err)
		}
	})

	t.Run("--interval loops until ctx cancel, surviving tick errors", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		calls, logged := 0, 0
		err := runDispatchLoop(ctx, false, time.Millisecond, func() error {
			calls++
			if calls == 3 {
				cancel()
			}
			return errors.New("transient forge error")
		}, func(string, ...any) { logged++ })
		if err != nil {
			t.Fatalf("loop err = %v, want nil on cancel", err)
		}
		if calls != 3 {
			t.Fatalf("calls = %d, want 3 (loop kept going after errors, stopped on cancel)", calls)
		}
		if logged < 2 {
			t.Errorf("logged = %d, want the tick errors reported", logged)
		}
	})
}

func TestValidateDispatchFlags(t *testing.T) {
	tests := []struct {
		name            string
		once            bool
		interval        time.Duration
		intervalChanged bool
		wantErr         string
	}{
		{name: "default loop", interval: 60 * time.Second},
		{name: "once", once: true, interval: 60 * time.Second},
		{name: "explicit interval", interval: 5 * time.Minute, intervalChanged: true},
		{name: "once with interval", once: true, interval: time.Minute, intervalChanged: true, wantErr: "mutually exclusive"},
		{name: "interval too short", interval: 100 * time.Millisecond, intervalChanged: true, wantErr: "at least"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateDispatchFlags(tt.once, tt.interval, tt.intervalChanged)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("err = %v, want one containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestParseDispatchStateFlag(t *testing.T) {
	tests := []struct {
		in      string
		want    pb.TrackerDispatchState
		wantErr bool
	}{
		{"", pb.TrackerDispatchState_TRACKER_DISPATCH_STATE_UNSPECIFIED, false},
		{"queued", pb.TrackerDispatchState_TRACKER_DISPATCH_STATE_QUEUED, false},
		{"RUNNING", pb.TrackerDispatchState_TRACKER_DISPATCH_STATE_RUNNING, false},
		{"done", pb.TrackerDispatchState_TRACKER_DISPATCH_STATE_DONE, false},
		{"failed", pb.TrackerDispatchState_TRACKER_DISPATCH_STATE_FAILED, false},
		{"unspecified", 0, true},
		{"stuck", 0, true},
	}
	for _, tt := range tests {
		got, err := parseDispatchStateFlag(tt.in)
		if (err != nil) != tt.wantErr {
			t.Errorf("parseDispatchStateFlag(%q) err = %v, wantErr %v", tt.in, err, tt.wantErr)
			continue
		}
		if !tt.wantErr && got != tt.want {
			t.Errorf("parseDispatchStateFlag(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

// httpModeStub points the CLI at a stub gateway for one test.
func httpModeStub(t *testing.T, respBody string) (gotMethod, gotPath, gotQuery *string) {
	t.Helper()
	var m, p, q string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m, p, q = r.Method, r.URL.Path, r.URL.RawQuery
		_, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, respBody)
	}))
	t.Cleanup(srv.Close)
	oldServer, oldHTTP, oldToken := serverAddr, httpMode, authToken
	t.Cleanup(func() { serverAddr, httpMode, authToken = oldServer, oldHTTP, oldToken })
	serverAddr, httpMode, authToken = srv.URL, true, "tok"
	return &m, &p, &q
}

func TestTrackerDispatch_HTTPModeOnceHitsGatewayPath(t *testing.T) {
	method, path, _ := httpModeStub(t, `{"started":[{"id":"d1","issueNumber":"42","scope":"product","skillId":"product-define","runId":"run-1","state":"TRACKER_DISPATCH_STATE_QUEUED"}],"skippedUnrouted":1}`)
	oldOnce := trackerDispatchOnce
	t.Cleanup(func() { trackerDispatchOnce = oldOnce })
	trackerDispatchOnce = true

	out := captureStdout(t, func() {
		if err := runTrackerDispatch(trackerDispatchCmd, []string{"alice", "default"}); err != nil {
			t.Errorf("runTrackerDispatch: %v", err)
		}
	})
	if *method != http.MethodPost || *path != "/v1/tracker/alice/default/dispatch" {
		t.Errorf("%s %s, want POST /v1/tracker/alice/default/dispatch", *method, *path)
	}
	if !strings.Contains(out, "#42") || !strings.Contains(out, "scope:product") || !strings.Contains(out, "run-1") {
		t.Errorf("output = %q, want the started issue, label and run id", out)
	}
	if !strings.Contains(out, "unrouted=1") {
		t.Errorf("output = %q, want the skip counts", out)
	}
}

func TestTrackerDispatches_HTTPModeHitsGatewayPath(t *testing.T) {
	method, path, query := httpModeStub(t, `{"dispatches":[{"id":"d1","issueNumber":"42","scope":"product","skillId":"product-define","runId":"run-1","state":"TRACKER_DISPATCH_STATE_FAILED","failureReason":"run did not start: boom"}]}`)
	oldState := trackerDispatchesState
	t.Cleanup(func() { trackerDispatchesState = oldState })
	trackerDispatchesState = "failed"

	out := captureStdout(t, func() {
		if err := runTrackerDispatches(trackerDispatchesCmd, []string{"alice", "default"}); err != nil {
			t.Errorf("runTrackerDispatches: %v", err)
		}
	})
	if *method != http.MethodGet || *path != "/v1/tracker/alice/default/dispatches" || *query != "state=TRACKER_DISPATCH_STATE_FAILED" {
		t.Errorf("%s %s?%s, want GET .../dispatches?state=TRACKER_DISPATCH_STATE_FAILED", *method, *path, *query)
	}
	if !strings.Contains(out, "failed") || !strings.Contains(out, "run did not start: boom") {
		t.Errorf("output = %q, want the state and failure reason", out)
	}
}

func TestPrintTrackerDispatches_Empty(t *testing.T) {
	out := captureStdout(t, func() { printTrackerDispatches("alice", "default", nil) })
	if !strings.Contains(out, "no dispatches") {
		t.Errorf("output = %q, want a placeholder", out)
	}
}
