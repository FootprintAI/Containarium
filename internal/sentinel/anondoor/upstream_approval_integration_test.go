//go:build integration

package anondoor

import (
	"os"
	"testing"
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
