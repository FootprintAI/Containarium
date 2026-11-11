package server

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/footprintai/containarium/internal/netbpf"
	"github.com/footprintai/containarium/internal/netpolicy"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// failingSigStore wraps a real store and fails List while fail is set.
type failingSigStore struct {
	NetworkPolicySignatureStore
	fail bool
}

func (f *failingSigStore) List(ctx context.Context) ([]*pb.NetworkPolicySignature, error) {
	if f.fail {
		return nil, errors.New("signature store unreachable")
	}
	return f.NetworkPolicySignatureStore.List(ctx)
}

// A store error must keep the last good merged set (#3519): the fingerprint is
// unchanged, so the next refresh does not clear operator signatures that are
// already loaded in BPF. The degraded state is reported and clears on recovery.
func TestEffectiveSignatures_StoreErrorKeepsLastGood(t *testing.T) {
	ctx := context.Background()
	store := &failingSigStore{NetworkPolicySignatureStore: NewMemNetworkPolicySignatureStore()}
	if _, err := store.Set(ctx, "op-active", []byte("AAAA"), true, ""); err != nil {
		t.Fatal(err)
	}
	e := &NetworkPolicyEnforcer{sigStore: store, ctx: ctx}

	good, goodFP := e.effectiveSignatures()
	if e.SignatureStoreDegraded() {
		t.Fatal("healthy store must not be degraded")
	}

	store.fail = true
	sigs, fp := e.effectiveSignatures()
	if fp != goodFP {
		t.Error("fingerprint changed on a store error; the next refresh would drop operator signatures")
	}
	if len(sigs) != len(good) || sigs[len(sigs)-1].Name != "op-active" {
		t.Errorf("operator signature missing from the kept set: %+v", sigs)
	}
	if !e.SignatureStoreDegraded() {
		t.Error("a store error must set the degraded state")
	}

	store.fail = false
	if _, err := store.Set(ctx, "op-new", []byte("CCCC"), true, ""); err != nil {
		t.Fatal(err)
	}
	sigs, fp = e.effectiveSignatures()
	if e.SignatureStoreDegraded() {
		t.Error("degraded state must clear when the store answers")
	}
	if fp == goodFP || len(sigs) != len(good)+1 {
		t.Error("recovery must pick up the store's current set")
	}
}

// The degraded signature store is visible in the tenant status and absent once
// the store recovers (#3519). Reported in every state while the enforcer runs.
func TestNetworkPolicyStatus_OperatorSignaturesStale(t *testing.T) {
	stale := pb.NetworkPolicyUncoveredPath_NETWORK_POLICY_UNCOVERED_PATH_OPERATOR_SIGNATURES_STALE

	snap := fresh(tenantApplied{BoxesLoaded: 1, Mode: netbpf.ModeEnforce})
	snap.SignaturesDegraded = true
	if st := npStatusFor(t, fakeAppliedSource{snap}, true, "acme"); !slices.Contains(st.GetUncoveredPaths(), stale) {
		t.Errorf("degraded store: uncovered paths %v lack OPERATOR_SIGNATURES_STALE", st.GetUncoveredPaths())
	}

	snap.SignaturesDegraded = false
	if st := npStatusFor(t, fakeAppliedSource{snap}, true, "acme"); slices.Contains(st.GetUncoveredPaths(), stale) {
		t.Errorf("recovered store: uncovered paths %v still list OPERATOR_SIGNATURES_STALE", st.GetUncoveredPaths())
	}
}

// The enforcer feeds its degraded flag into the applied snapshot.
func TestAppliedState_CarriesSignatureDegraded(t *testing.T) {
	e := &NetworkPolicyEnforcer{running: true, sigDegraded: true}
	if !e.AppliedState("acme").SignaturesDegraded {
		t.Error("AppliedState must report the degraded signature store")
	}
}

// With no good read yet, a store error falls back to built-ins and is degraded.
func TestEffectiveSignatures_StoreErrorBeforeFirstGoodRead(t *testing.T) {
	store := &failingSigStore{NetworkPolicySignatureStore: NewMemNetworkPolicySignatureStore(), fail: true}
	e := &NetworkPolicyEnforcer{sigStore: store, ctx: context.Background()}
	sigs, _ := e.effectiveSignatures()
	if len(sigs) != len(netpolicy.BuiltinSignatures()) {
		t.Errorf("want built-ins only, got %d", len(sigs))
	}
	if !e.SignatureStoreDegraded() {
		t.Error("want degraded")
	}
}
