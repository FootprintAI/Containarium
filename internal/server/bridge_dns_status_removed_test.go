package server

import (
	"strings"
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// #2733 (slice B of #2263): the bridge-DNS status surface is gone from the
// contract. The kernel hairpin rule (#2732) replaces the record it reported on.
func TestBridgeDNSStatusRemovedFromContract(t *testing.T) {
	svc := pb.File_containarium_v1_service_proto.Services().ByName("ContainerService")
	if svc == nil {
		t.Fatal("ContainerService not found in the generated descriptor; test harness broken")
	}
	if m := svc.Methods().ByName("GetBridgeDNSStatus"); m != nil {
		t.Errorf("ContainerService still has %s", m.FullName())
	}
	for _, name := range []protoreflect.FullName{
		"containarium.v1.BridgeDNSState",
		"containarium.v1.GetBridgeDNSStatusRequest",
		"containarium.v1.GetBridgeDNSStatusResponse",
	} {
		if _, err := protoregistry.GlobalFiles.FindDescriptorByName(name); err == nil {
			t.Errorf("%s is still registered", name)
		}
	}
}

// The built-in bridge_dns_alerts group went with its gauges; every remaining
// default rule still carries source=default (moved here from the deleted
// bridge_dns_metrics_test.go so the check is not lost).
func TestDefaultAlertRulesHaveNoBridgeDNSGroup(t *testing.T) {
	rules, err := parseDefaultAlertRules()
	if err != nil {
		t.Fatalf("DefaultAlertRules no longer parses: %v", err)
	}
	if len(rules) == 0 {
		t.Fatal("no default rules parsed; test harness broken")
	}
	for _, r := range rules {
		if strings.HasPrefix(r.GetName(), "BridgeDNS") || strings.Contains(r.GetExpr(), "bridge_dns_") {
			t.Errorf("default rule %s (%q) still targets the removed bridge DNS series", r.GetName(), r.GetExpr())
		}
	}
	if strings.Contains(DefaultAlertRules, "bridge_dns_alerts") {
		t.Error("DefaultAlertRules still has the bridge_dns_alerts group")
	}
	if got := strings.Count(DefaultAlertRules, "source: default"); got != strings.Count(DefaultAlertRules, "- alert:") {
		t.Errorf("%d rules but %d carry source: default", strings.Count(DefaultAlertRules, "- alert:"), got)
	}
}
