package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/runner"
	"github.com/footprintai/containarium/pkg/core/incus"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/encoding/protojson"
)

// hostile is a tenant-supplied string that, printed raw, clears the
// operator's screen (ESC), rewinds the line (CR) and forges a whole new
// output row (LF + TAB) in the table that follows (#3343).
const hostile = "evil\x1b[2J\r\nFORGED\tcell"

// escapedHostile is what escapeControl turns it into: every control byte
// shown as its Go escape, so the value is visible but inert.
const escapedHostile = `evil\x1b[2J\r\nFORGED\tcell`

// assertNoRawControl fails when out still carries a raw control byte from
// hostile, or when hostile managed to start a forged line of its own.
func assertNoRawControl(t *testing.T, out string) {
	t.Helper()
	for _, raw := range []string{"\x1b", "\r"} {
		if strings.Contains(out, raw) {
			t.Errorf("output carries a raw control byte %q:\n%q", raw, out)
		}
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "FORGED") {
			t.Errorf("a tenant value forged its own output line %q in:\n%q", line, out)
		}
	}
	if strings.Contains(out, "FORGED\tcell") {
		t.Errorf("a tenant value injected a raw TAB (a fake tabwriter cell):\n%q", out)
	}
	// Proves the hostile value was printed at all (escaped), so the test
	// cannot pass by the cell simply disappearing.
	if !strings.Contains(out, `evil\x1b`) {
		t.Errorf("output does not show the escaped tenant value:\n%q", out)
	}
}

// Every CLI table / list cell holding a tenant-supplied value prints it
// through escapeControl: a tenant cannot drive the operator's terminal or
// forge rows (#3343).
func TestCLITables_EscapeTenantSuppliedCells(t *testing.T) {
	ts := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	stdout := func(fn func()) func(t *testing.T) string {
		return func(t *testing.T) string { return captureStdout(t, fn) }
	}
	writer := func(fn func(w *bytes.Buffer)) func(t *testing.T) string {
		return func(*testing.T) string {
			var b bytes.Buffer
			fn(&b)
			return b.String()
		}
	}

	cases := []struct {
		name string
		run  func(t *testing.T) string
	}{
		{"list: container name", stdout(func() {
			printTableFormat([]incus.ContainerInfo{{Name: hostile, State: "Running"}}, 1, 0, false)
		})},
		{"list: label value", stdout(func() {
			printTableFormat([]incus.ContainerInfo{{Name: "box", State: "Running", Labels: map[string]string{"team": hostile}}}, 1, 0, true)
		})},
		{"list: label key", stdout(func() {
			printTableFormat([]incus.ContainerInfo{{Name: "box", State: "Running", Labels: map[string]string{hostile: "v"}}}, 1, 0, true)
		})},
		{"list --group-by: group header and name", stdout(func() {
			printGroupedTableFormat([]incus.ContainerInfo{{Name: hostile, State: "Running", Labels: map[string]string{"team": hostile}}}, "team", false)
		})},
		{"app list: name, domain, user", stdout(func() {
			printAppTableFormat([]*pb.App{{Name: hostile, FullDomain: hostile, Username: hostile}}, 1)
		})},
		{"route list: domain", stdout(func() {
			printRouteTableFormat([]*pb.ProxyRoute{{FullDomain: hostile}}, 1)
		})},
		{"passthrough route list: container", stdout(func() {
			printPassthroughRouteTableFormat([]*pb.PassthroughRoute{{ContainerName: hostile}}, 1)
		})},
		{"collaborator list: container header", stdout(func() {
			printCollaboratorTable(hostile, []collaboratorRow{{CollaboratorUsername: "u", AccountName: "a", CreatedAt: ts}})
		})},
		{"collaborator list: username, account, added-by", stdout(func() {
			printCollaboratorTable("box", []collaboratorRow{{CollaboratorUsername: hostile, AccountName: hostile, CreatedAt: ts, CreatedBy: hostile}})
		})},
		{"backup list: user and database", writer(func(w *bytes.Buffer) {
			_ = printBackupList(w, []*pb.BackupRecord{{Id: "1", Username: hostile, Database: hostile}})
		})},
		{"cluster show: name, owner, reason, node group", writer(func(w *bytes.Buffer) {
			printClusterTo(w, &pb.Cluster{Name: hostile, Owner: hostile, StateReason: hostile, NodeGroups: []*pb.NodeGroup{{Name: hostile, Size: &pb.ResourceLimits{}}}})
		})},
		{"cluster list: name and owner", writer(func(w *bytes.Buffer) {
			_ = writeClusterList(w, []*pb.Cluster{{Name: hostile, Owner: hostile}})
		})},
		{"runner list: name and note", stdout(func() {
			printRunnerTable([]runner.RunnerStatus{{Name: hostile, LastError: hostile}})
		})},
		{"network guard: container", writer(func(w *bytes.Buffer) {
			printGuard(w, "guard", "", &guardStatusJSON{Entries: []guardEntryJSON{{Container: hostile}}})
		})},
		{"tracker route list: label scope and skill", stdout(func() {
			printTrackerRoutes("u", "c", []*pb.TrackerRoute{{Scope: hostile, SkillId: hostile}})
		})},
		{"tracker dispatch list: scope, skill, failure reason", stdout(func() {
			printTrackerDispatches("u", "c", []*pb.TrackerDispatch{{Scope: hostile, SkillId: hostile, FailureReason: hostile}})
		})},
		{"tracker list: name, project, credential secret", stdout(func() {
			printTrackerConnections([]*pb.TrackerConnection{{Name: hostile, Project: hostile, CredentialSecret: hostile}})
		})},
		{"tracker issue list: labels and title", stdout(func() {
			printTrackerIssueList([]*pb.TrackerIssue{{Number: 1, Labels: []string{hostile}, Title: hostile}})
		})},
		{"gateway models: model id", stdout(func() {
			printGatewayModels(&pb.ListGatewayModelsResponse{KeyOwner: "u", Models: []*pb.GatewayModel{{Id: hostile}}})
		})},
		{"gateway models: key owner", stdout(func() {
			printGatewayModels(&pb.ListGatewayModelsResponse{KeyOwner: hostile})
		})},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assertNoRawControl(t, tc.run(t))
		})
	}
}

// escapedHostile is the exact rendering the tables show; pinning it keeps
// the helper's output stable for operators grepping CLI output.
func TestEscapeControl_HostileRendering(t *testing.T) {
	if got := escapeControl(hostile); got != escapedHostile {
		t.Errorf("escapeControl(hostile) = %q, want %q", got, escapedHostile)
	}
}

// Finding subjects and evidence are written by processes inside a tenant
// box (filenames, comm, sshd config values, listener binaries); the
// findings table must not let them drive the operator's terminal (#3343).
func TestRunSecurityFindingsList_EscapesTenantEvidence(t *testing.T) {
	findings := []*pb.Finding{
		{Id: 1, TenantId: hostile, Subject: hostile},
		{Id: 2, Subject: "s", Evidence: &pb.Evidence{Configs: []*pb.ConfigEvidence{{Directive: hostile, Value: hostile, Path: hostile, Note: hostile}}}},
		{Id: 3, Subject: "s", Evidence: &pb.Evidence{Execs: []*pb.ExecEvidence{{Filename: hostile, Comm: hostile}}}},
		{Id: 4, Subject: "s", Evidence: &pb.Evidence{Listeners: []*pb.ListenerEvidence{{Binary: hostile, Note: hostile}}}},
	}
	for _, f := range findings {
		body, err := protojson.Marshal(&pb.ListFindingsResponse{Findings: []*pb.Finding{f}})
		if err != nil {
			t.Fatal(err)
		}
		t.Run(fmt.Sprintf("finding %d", f.Id), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write(body)
			}))
			defer srv.Close()
			oldServer := serverAddr
			serverAddr = srv.URL
			defer func() { serverAddr = oldServer }()
			cmd := testCmd()
			var buf bytes.Buffer
			cmd.SetOut(&buf)
			if err := runSecurityFindingsList(cmd, nil); err != nil {
				t.Fatalf("runSecurityFindingsList: %v", err)
			}
			assertNoRawControl(t, buf.String())
		})
	}
}

// `traffic find` names the box on every row; the box name is tenant-chosen.
func TestTrafficFind_EscapesBoxName(t *testing.T) {
	body, err := json.Marshal(queryHistoryResp{
		Connections: []historicalConnection{{ContainerName: hostile, Protocol: "PROTOCOL_TCP", StartedAt: "2026-10-20T10:30:00Z"}},
		TotalCount:  1,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, _, out := runTrafficStub(t, string(body), func(cmd *cobra.Command) error {
		trafficDestIP = "203.0.113.9"
		trafficFrom, trafficTo = "2026-10-20T10:00:00Z", "2026-10-20T11:00:00Z"
		defer func() { trafficFrom, trafficTo = "", "" }()
		return runTrafficFind(cmd, nil)
	})
	assertNoRawControl(t, out)
}
