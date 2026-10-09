//go:build !windows && !containarium_client

package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/footprintai/containarium/internal/sentinel/sshsession"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/spf13/cobra"
)

// #2415 — `containarium sentinel ssh-sessions ship`.

type ingestStub struct {
	mu   sync.Mutex
	auth []string
	reqs []*pb.IngestSSHSessionRecordsRequest
	seen map[string]bool
	srv  *httptest.Server
	fail bool
}

func newIngestStub(t *testing.T) *ingestStub {
	t.Helper()
	s := &ingestStub{seen: map[string]bool{}}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		if r.URL.Path != "/v1/audit/ssh-sessions/ingest" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		if s.fail {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		b, _ := io.ReadAll(r.Body)
		var req pb.IngestSSHSessionRecordsRequest
		if err := protojson.Unmarshal(b, &req); err != nil {
			t.Errorf("stub: bad body: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		s.auth = append(s.auth, r.Header.Get("Authorization"))
		s.reqs = append(s.reqs, &req)
		resp := &pb.IngestSSHSessionRecordsResponse{}
		for _, rec := range req.Records {
			k := rec.SessionId + "|" + rec.Phase.String() + "|" + rec.CloseReason.String()
			if s.seen[k] {
				resp.Outcomes = append(resp.Outcomes, pb.IngestOutcome_INGEST_OUTCOME_DUPLICATE)
				resp.Duplicates++
			} else {
				s.seen[k] = true
				resp.Outcomes = append(resp.Outcomes, pb.IngestOutcome_INGEST_OUTCOME_INSERTED)
				resp.Inserted++
			}
		}
		out, _ := protojson.Marshal(resp)
		_, _ = w.Write(out)
	}))
	t.Cleanup(s.srv.Close)
	return s
}

func (s *ingestStub) records() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, r := range s.reqs {
		n += len(r.Records)
	}
	return n
}

type shipFixture struct {
	dir     string
	records string
	ckpt    string
	stub    *ingestStub
}

func newShipFixture(t *testing.T) *shipFixture {
	t.Helper()
	dir := t.TempDir()
	return &shipFixture{
		dir: dir, records: filepath.Join(dir, "ssh-sessions.jsonl"),
		ckpt: filepath.Join(dir, "ckpt", "checkpoint.json"), stub: newIngestStub(t),
	}
}

func (f *shipFixture) write(t *testing.T, recs ...sshsession.Record) {
	t.Helper()
	fh, err := os.OpenFile(f.records, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer fh.Close()
	for _, r := range recs {
		b, _ := json.Marshal(r)
		_, _ = fh.Write(append(b, '\n'))
	}
}

func shipRec(id string, phase sshsession.SessionPhase, at time.Time) sshsession.Record {
	r := sshsession.Record{SessionID: id, Phase: phase, OccurredAt: at, ClientIP: "203.0.113.1", Login: "alice",
		AuthMethod: sshsession.AuthMethodPublicKey, Credential: sshsession.Credential{KeyFingerprint: "SHA256:x"}}
	if phase == sshsession.SessionPhaseClose {
		r.CloseReason = sshsession.CloseReasonNormal
	}
	return r
}

// runShip runs `ship` through cobra with args, so flag wiring is exercised.
func runShip(t *testing.T, args ...string) (string, error) {
	t.Helper()
	root := &cobra.Command{Use: "root"}
	root.AddCommand(&cobra.Command{Use: "x"}) // keep the tree non-trivial
	var out bytes.Buffer
	c := newSentinelSSHSessionsShipCmd()
	root.AddCommand(c)
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs(append([]string{"ship"}, args...))
	err := root.ExecuteContext(context.Background())
	return out.String(), err
}

func (f *shipFixture) baseArgs() []string {
	return []string{"--records-file", f.records, "--checkpoint-file", f.ckpt, "--url", f.stub.srv.URL, "--token", "tok-1"}
}

func TestShipCmd_OnceShipsFixtureAndRerunAddsNothing(t *testing.T) {
	f := newShipFixture(t)
	at := time.Now().Add(-time.Hour)
	f.write(t, shipRec("s1", sshsession.SessionPhaseOpen, at), shipRec("s2", sshsession.SessionPhaseOpen, at), shipRec("s1", sshsession.SessionPhaseClose, at))

	out, err := runShip(t, append(f.baseArgs(), "--once")...)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if got := f.stub.records(); got != 3 {
		t.Fatalf("shipped %d records, want 3", got)
	}
	if f.stub.auth[0] != "Bearer tok-1" {
		t.Fatalf("Authorization = %q", f.stub.auth[0])
	}
	if !strings.Contains(out, "shipped=3") {
		t.Fatalf("summary line missing counts: %q", out)
	}

	if _, err := runShip(t, append(f.baseArgs(), "--once")...); err != nil {
		t.Fatal(err)
	}
	if got := f.stub.records(); got != 3 {
		t.Fatalf("a rerun must add 0 records; stub now has %d", got)
	}
}

func TestShipCmd_ReadsTokenFromFile(t *testing.T) {
	f := newShipFixture(t)
	f.write(t, shipRec("s1", sshsession.SessionPhaseOpen, time.Now()))
	tf := filepath.Join(f.dir, "token")
	_ = os.WriteFile(tf, []byte("  tok-from-file\n"), 0o600)

	args := []string{"--records-file", f.records, "--checkpoint-file", f.ckpt, "--url", f.stub.srv.URL, "--token-file", tf, "--once"}
	if out, err := runShip(t, args...); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if f.stub.auth[0] != "Bearer tok-from-file" {
		t.Fatalf("Authorization = %q (token file must be trimmed)", f.stub.auth[0])
	}
}

func TestShipCmd_ErrorsWhenBackendUnavailable(t *testing.T) {
	f := newShipFixture(t)
	f.write(t, shipRec("s1", sshsession.SessionPhaseOpen, time.Now()))
	f.stub.fail = true
	if _, err := runShip(t, append(f.baseArgs(), "--once")...); err == nil {
		t.Fatal("--once must exit non-zero when the batch could not be shipped (so cron/CI notices)")
	}
	f.stub.fail = false
	if _, err := runShip(t, append(f.baseArgs(), "--once")...); err != nil {
		t.Fatal(err)
	}
	if f.stub.records() != 1 {
		t.Fatalf("records after recovery = %d, want 1", f.stub.records())
	}
}

func TestShipCmd_Reconcile(t *testing.T) {
	f := newShipFixture(t)
	f.write(t, shipRec("orphan", sshsession.SessionPhaseOpen, time.Now().Add(-72*time.Hour)),
		shipRec("fresh", sshsession.SessionPhaseOpen, time.Now().Add(-time.Minute)))

	out, err := runShip(t, append(f.baseArgs(), "--reconcile", "--orphan-after", "24h")...)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if f.stub.records() != 1 {
		t.Fatalf("reconcile sent %d records, want exactly the one orphan close", f.stub.records())
	}
	got := f.stub.reqs[0].Records[0]
	if got.SessionId != "orphan" || got.CloseReason != pb.SSHCloseReason_SSH_CLOSE_REASON_UNKNOWN_ORPHAN {
		t.Fatalf("sent %+v", got)
	}
	if !strings.Contains(out, "orphans_closed=1") {
		t.Fatalf("summary = %q", out)
	}
	// Reconcile never touches the checkpoint or the sink.
	if _, err := os.Stat(f.ckpt); err == nil {
		t.Fatal("--reconcile alone must not write a shipper checkpoint")
	}
}

func TestShipCmd_FlagValidation(t *testing.T) {
	f := newShipFixture(t)
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"no url", []string{"--records-file", f.records, "--token", "t", "--once"}, "--url"},
		{"no token", []string{"--records-file", f.records, "--url", f.stub.srv.URL, "--once"}, "token"},
		{"both token sources", append(f.baseArgs(), "--token-file", "x", "--once"), "exactly one"},
		{"reconcile needs positive threshold", append(f.baseArgs(), "--reconcile", "--orphan-after", "0"), "orphan-after"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("CONTAINARIUM_AUDIT_INGEST_TOKEN", "")
			_, err := runShip(t, tc.args...)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

// The in-process shipper is on by default: the audit gap (#2415) is the
// default state, so opting in would leave most sentinels unshipped.
func TestSentinelCmd_ShipperFlagDefaults(t *testing.T) {
	for name, want := range map[string]string{
		"ssh-session-shipper":         "true",
		"ssh-session-records-file":    sshsession.DefaultRecordsFile,
		"ssh-session-checkpoint-file": sshsession.DefaultCheckpointFile,
		"ssh-session-ship-interval":   "5s",
	} {
		fl := sentinelCmd.Flags().Lookup(name)
		if fl == nil {
			t.Fatalf("sentinel is missing --%s", name)
		}
		if fl.DefValue != want {
			t.Errorf("--%s default = %q, want %q", name, fl.DefValue, want)
		}
	}
}
