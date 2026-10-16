//go:build integration

package anondoor

import (
	"github.com/footprintai/containarium/internal/sentinel/sshcontrol"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/protobuf/types/known/durationpb"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// TestIntegration_PublicKeyApprovalThroughTransportAdapter reruns the established
// signature/partial-success/approval assertions through the new routing hook.
func TestIntegration_PublicKeyApprovalThroughTransportAdapter(t *testing.T) {
	adapter := os.Getenv("SSH_BAN_DAEMON")
	if adapter == "" || os.Getenv("ANONDOOR_SSHPIPERD") == "" {
		t.Fatal("set SSH_BAN_DAEMON and ANONDOOR_SSHPIPERD; transport approval prerequisites are mandatory")
	}
	t.Setenv("ANONDOOR_APPROVAL_ADAPTER", adapter)
	TestIntegration_PublicKeyPartialSuccessKeyboardInteractive(t)
}

// TestIntegration_PublicKeyApprovalThroughGuardedAdapter includes shared control.
func TestIntegration_PublicKeyApprovalThroughGuardedAdapter(t *testing.T) {
	t.Setenv("ANONDOOR_APPROVAL_GUARDED", "1")
	TestIntegration_PublicKeyApprovalThroughTransportAdapter(t)
}

// approvalGuardControl provides the same private contract to the full approval flow.
func approvalGuardControl(t *testing.T, endpoint string) (string, string) {
	t.Helper()
	dir, err := os.MkdirTemp("", "approval-control-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	var offset atomic.Int64
	offset.Store(int64(-time.Minute))
	p := &pb.SSHUpstreamPolicy{InitialDelay: durationpb.New(time.Second), MaxDelay: durationpb.New(8 * time.Second), Window: durationpb.New(time.Minute), SetupTimeout: durationpb.New(30 * time.Second), FailureBudget: 2, RiskPerAttempt: 1, MaxBackends: 8, MaxPending: 8, MaxConnections: 32, EgressGroup: "approval-fixture", Routes: []*pb.SSHUpstreamRoute{{BackendId: "backend", Endpoint: endpoint}}}
	c, err := sshcontrol.New(sshcontrol.Config{Policy: p, StatePath: filepath.Join(dir, "risk.json"), Now: func() time.Time { return time.Now().Add(time.Duration(offset.Load())) }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	offset.Store(0)
	socket := filepath.Join(dir, "control.sock")
	stop, err := sshcontrol.ListenControl(socket, c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(stop)
	return socket, filepath.Join(dir, "ban", "control.sock")
}
