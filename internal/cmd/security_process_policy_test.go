package cmd

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/durationpb"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// policyServer is an in-process stand-in for the daemon's REST surface: it
// records the last request and replies with a canned protojson body.
type policyServer struct {
	method, path, query string
	body                []byte
	reply               string
	status              int
}

func (p *policyServer) start(t *testing.T) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.method, p.path, p.query = r.Method, r.URL.Path, r.URL.RawQuery
		p.body, _ = io.ReadAll(r.Body)
		if p.status != 0 {
			w.WriteHeader(p.status)
		}
		w.Write([]byte(p.reply))
	}))
	t.Cleanup(srv.Close)
	old := serverAddr
	serverAddr = srv.URL
	t.Cleanup(func() { serverAddr = old })
}

func runPolicySet(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := newProcessPolicySetCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return buf.String(), err
}

func TestProcessPolicySet_FlagParsing(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr string // substring; empty = success
		check   func(t *testing.T, req *pb.SetProcessPolicyRequest)
	}{
		{
			name: "throttle with allowance and ttl",
			args: []string{"--action", "throttle", "--throttle-allowance", "20%", "--ttl", "2h"},
			check: func(t *testing.T, r *pb.SetProcessPolicyRequest) {
				p := r.GetPolicy()
				if p.GetAction() != pb.ProcessAction_PROCESS_ACTION_THROTTLE || p.GetThrottleAllowance() != "20%" ||
					p.GetTtl().AsDuration() != 2*time.Hour || r.GetContainer() != "" {
					t.Errorf("req = %v", r)
				}
			},
		},
		{
			name: "freeze override on a container, case-insensitive",
			args: []string{"--action", "FREEZE", "--container", "box-1"},
			check: func(t *testing.T, r *pb.SetProcessPolicyRequest) {
				if r.GetContainer() != "box-1" || r.GetPolicy().GetAction() != pb.ProcessAction_PROCESS_ACTION_FREEZE {
					t.Errorf("req = %v", r)
				}
			},
		},
		{
			name: "clear override",
			args: []string{"--container", "box-1", "--clear-override"},
			check: func(t *testing.T, r *pb.SetProcessPolicyRequest) {
				if !r.GetClearOverride() || r.GetContainer() != "box-1" {
					t.Errorf("req = %v", r)
				}
			},
		},
		{
			name: "mining-behavior thresholds",
			args: []string{"--rule", "mining-behavior", "--min-cores", "2", "--min-fraction-of-limit", "0.5",
				"--window", "10m", "--flow-min-age", "4m", "--stratum-ports", "3333,4444"},
			check: func(t *testing.T, r *pb.SetProcessPolicyRequest) {
				m := r.GetPolicy().GetMiningBehavior()
				if m.GetMinCores() != 2 || m.GetMinFractionOfLimit() != 0.5 ||
					m.GetWindow().AsDuration() != 10*time.Minute || m.GetFlowMinAge().AsDuration() != 4*time.Minute ||
					len(m.GetStratumPorts()) != 2 || m.GetStratumPorts()[1] != 4444 {
					t.Errorf("mining = %v", m)
				}
				if r.GetPolicy().GetAction() != pb.ProcessAction_PROCESS_ACTION_UNSPECIFIED {
					t.Errorf("action must stay unset, got %v", r.GetPolicy().GetAction())
				}
			},
		},
		{name: "unknown action", args: []string{"--action", "kill"}, wantErr: "alert, throttle, freeze"},
		{name: "bad allowance", args: []string{"--action", "throttle", "--throttle-allowance", "fast"}, wantErr: "throttle-allowance"},
		{name: "bad ttl", args: []string{"--action", "alert", "--ttl", "tomorrow"}, wantErr: "--ttl"},
		{name: "negative ttl", args: []string{"--action", "alert", "--ttl", "-1h"}, wantErr: "--ttl"},
		{name: "nothing to set", args: []string{}, wantErr: "nothing to set"},
		{name: "clear-override with action", args: []string{"--container", "b", "--clear-override", "--action", "freeze"}, wantErr: "--clear-override cannot be combined with policy flags"},
		{name: "clear-override with ttl", args: []string{"--container", "b", "--clear-override", "--ttl", "1h"}, wantErr: "--clear-override cannot be combined with policy flags"},
		{name: "clear-override with allowance", args: []string{"--container", "b", "--clear-override", "--throttle-allowance", "10%"}, wantErr: "--clear-override cannot be combined with policy flags"},
		{name: "clear-override with rule", args: []string{"--container", "b", "--clear-override", "--rule", "mining-behavior"}, wantErr: "--clear-override cannot be combined with policy flags"},
		{name: "mining rule without thresholds", args: []string{"--rule", "mining-behavior"}, wantErr: "at least one threshold flag is required with --rule mining-behavior"},
		{name: "clear-override needs container", args: []string{"--clear-override"}, wantErr: "--container"},
		{name: "unknown rule", args: []string{"--rule", "deny-burst", "--min-cores", "1"}, wantErr: "mining-behavior"},
		{name: "threshold flag without rule", args: []string{"--min-cores", "1"}, wantErr: "--rule mining-behavior"},
		{name: "thresholds are backend-wide", args: []string{"--rule", "mining-behavior", "--min-cores", "1", "--container", "b"}, wantErr: "backend-wide"},
		{name: "bad port", args: []string{"--rule", "mining-behavior", "--stratum-ports", "3333,99999"}, wantErr: "stratum-ports"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ps := &policyServer{reply: `{"effective":{"action":"PROCESS_ACTION_ALERT"}}`}
			ps.start(t)
			out, err := runPolicySet(t, tt.args...)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want containing %q", err, tt.wantErr)
				}
				if ps.method != "" {
					t.Errorf("rejected input must not reach the server (got %s %s)", ps.method, ps.path)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v\n%s", err, out)
			}
			if ps.method != http.MethodPut || ps.path != "/v1/security/process-policy" {
				t.Errorf("request = %s %s", ps.method, ps.path)
			}
			var req pb.SetProcessPolicyRequest
			if err := protojson.Unmarshal(ps.body, &req); err != nil {
				t.Fatalf("body is not a SetProcessPolicyRequest: %v\n%s", err, ps.body)
			}
			tt.check(t, &req)
		})
	}
}

func TestProcessPolicySet_SendsEnumNotString(t *testing.T) {
	ps := &policyServer{reply: `{}`}
	ps.start(t)
	if _, err := runPolicySet(t, "--action", "freeze"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(ps.body), `"PROCESS_ACTION_FREEZE"`) {
		t.Errorf("body = %s, want the proto enum name", ps.body)
	}
}

func TestProcessPolicyGet_RendersStoredAndEffective(t *testing.T) {
	eff := &pb.ProcessPolicy{Action: pb.ProcessAction_PROCESS_ACTION_THROTTLE, ThrottleAllowance: "10%", Ttl: durationpb.New(24 * time.Hour)}
	stored := &pb.ProcessPolicy{
		Action: pb.ProcessAction_PROCESS_ACTION_THROTTLE,
		MiningBehavior: &pb.MiningBehaviorThresholds{
			MinCores: 1.5, MinFractionOfLimit: 0.75, Window: durationpb.New(5 * time.Minute),
			FlowMinAge: durationpb.New(3 * time.Minute), StratumPorts: []uint32{3333, 4444},
		},
	}
	reply, _ := protojson.Marshal(&pb.GetProcessPolicyResponse{Policy: stored, IsOverride: true, Effective: eff})
	ps := &policyServer{reply: string(reply)}
	ps.start(t)

	cmd := newProcessPolicyGetCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{"--container", "box-1"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if ps.method != http.MethodGet || ps.path != "/v1/security/process-policy" || ps.query != "container=box-1" {
		t.Errorf("request = %s %s?%s", ps.method, ps.path, ps.query)
	}
	const golden = `Container: box-1
Stored:    THROTTLE (override)
Effective:
  action:             THROTTLE
  throttle allowance: 10%
  ttl:                24h0m0s
Mining-behavior thresholds:
  min cores:              1.5
  min fraction of limit:  0.75
  window:                 5m0s
  flow min age:           3m0s
  stratum ports:          3333,4444
`
	if buf.String() != golden {
		t.Errorf("output mismatch\n--- got ---\n%s--- want ---\n%s", buf.String(), golden)
	}
}

func TestProcessPolicyGet_BackendDefaultNothingStored(t *testing.T) {
	ps := &policyServer{reply: `{"effective":{"action":"PROCESS_ACTION_ALERT","throttleAllowance":"10%","ttl":"86400s"}}`}
	ps.start(t)
	cmd := newProcessPolicyGetCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if ps.query != "" {
		t.Errorf("no --container must not send one, query = %q", ps.query)
	}
	for _, want := range []string{"Backend default", "Stored:    (none", "action:             ALERT"} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("output missing %q:\n%s", want, buf.String())
		}
	}
}

func TestProcessPolicyGet_JSON(t *testing.T) {
	ps := &policyServer{reply: `{"effective":{"action":"PROCESS_ACTION_ALERT"}}`}
	ps.start(t)
	cmd := newProcessPolicyGetCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{"--json"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	var back pb.GetProcessPolicyResponse
	if err := protojson.Unmarshal(buf.Bytes(), &back); err != nil {
		t.Fatalf("--json is not the response's protojson: %v\n%s", err, buf.String())
	}
}

func TestProcessPolicyRelease(t *testing.T) {
	reply, _ := protojson.Marshal(&pb.ReleaseProcessActionResponse{Finding: &pb.Finding{
		Id: 42, Container: "box-1",
		Response: &pb.FindingResponse{Action: pb.ProcessAction_PROCESS_ACTION_THROTTLE, State: pb.ResponseState_RESPONSE_STATE_RELEASED, ReleasedBy: "operator"},
	}})
	ps := &policyServer{reply: string(reply)}
	ps.start(t)
	cmd := newProcessPolicyReleaseCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{"box-1"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if ps.method != http.MethodPost || ps.path != "/v1/security/process-policy/release" || !strings.Contains(string(ps.body), `"box-1"`) {
		t.Errorf("request = %s %s %s", ps.method, ps.path, ps.body)
	}
	const want = "Released THROTTLE on box-1: CPU limit restored. Finding #42 resolved.\n"
	if buf.String() != want {
		t.Errorf("output = %q, want %q", buf.String(), want)
	}
}

func TestProcessPolicyRelease_FreezeWording(t *testing.T) {
	reply, _ := protojson.Marshal(&pb.ReleaseProcessActionResponse{Finding: &pb.Finding{
		Id: 7, Response: &pb.FindingResponse{Action: pb.ProcessAction_PROCESS_ACTION_FREEZE},
	}})
	(&policyServer{reply: string(reply)}).start(t)
	cmd := newProcessPolicyReleaseCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{"box-2"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "unfrozen") || !strings.Contains(buf.String(), "#7") {
		t.Errorf("output = %q", buf.String())
	}
}

func TestProcessPolicyRelease_NotFoundAndArgs(t *testing.T) {
	ps := &policyServer{status: http.StatusNotFound, reply: `{"message":"no open action"}`}
	ps.start(t)
	cmd := newProcessPolicyReleaseCmd()
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{"box-1"})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "404") {
		t.Errorf("err = %v, want a 404 surfaced", err)
	}
	cmd = newProcessPolicyReleaseCmd()
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{})
	if err := cmd.Execute(); err == nil {
		t.Error("release without a container must fail")
	}
}

func TestProcessPolicy_RequiresServer(t *testing.T) {
	old := serverAddr
	serverAddr = ""
	defer func() { serverAddr = old }()
	cmd := newProcessPolicyGetCmd()
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected an error when --server is unset")
	}
}

func TestSentryStatus_PrintsDegradedNoPersistence(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"state":"SENTRY_STATE_DEGRADED","reason":"DEGRADED (no persistence): responses disabled"}`))
	}))
	defer srv.Close()
	old := serverAddr
	serverAddr = srv.URL
	defer func() { serverAddr = old }()
	cmd := testCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	if err := runSecuritySentryStatus(cmd, nil); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Sentry: DEGRADED", "Reason: DEGRADED (no persistence): responses disabled"} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("missing %q:\n%s", want, buf.String())
		}
	}
}
