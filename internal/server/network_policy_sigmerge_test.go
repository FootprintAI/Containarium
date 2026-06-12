package server

import (
	"context"
	"testing"

	"github.com/footprintai/containarium/internal/netbpf"
	"github.com/footprintai/containarium/internal/netpolicy"
)

// TestEffectiveSignatures_Merge covers the built-in + operator merge (#661 PR-B):
// built-ins first, disabled operator sigs skipped, capped to the BPF slot budget.
func TestEffectiveSignatures_Merge(t *testing.T) {
	store := NewMemNetworkPolicySignatureStore()
	ctx := context.Background()
	if _, err := store.Set(ctx, "op-active", []byte("AAAA"), true, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Set(ctx, "op-disabled", []byte("BBBB"), false, ""); err != nil {
		t.Fatal(err)
	}

	e := &NetworkPolicyEnforcer{sigStore: store, ctx: ctx}
	sigs, fp := e.effectiveSignatures()

	builtins := netpolicy.BuiltinSignatures()
	// built-ins + the one ENABLED operator signature (disabled one skipped).
	if len(sigs) != len(builtins)+1 {
		t.Fatalf("want %d signatures (built-ins + 1 active operator), got %d", len(builtins)+1, len(sigs))
	}
	// built-ins come first.
	for i, b := range builtins {
		if sigs[i].ID != b.ID {
			t.Errorf("slot %d: built-in order changed (id %d != %d)", i, sigs[i].ID, b.ID)
		}
	}
	last := sigs[len(sigs)-1]
	if last.Name != "op-active" || last.ID < netpolicy.OperatorIDBase {
		t.Errorf("operator signature wrong: %+v", last)
	}
	for _, s := range sigs {
		if s.Name == "op-disabled" {
			t.Error("disabled operator signature must not be loaded")
		}
	}

	// Fingerprint is stable for the same set and changes when a signature changes.
	_, fp2 := e.effectiveSignatures()
	if fp != fp2 {
		t.Error("fingerprint not stable across identical reads")
	}
	if _, err := store.Set(ctx, "op-active", []byte("CHANGED"), true, ""); err != nil {
		t.Fatal(err)
	}
	if _, fp3 := e.effectiveSignatures(); fp3 == fp {
		t.Error("fingerprint should change when a pattern changes")
	}
}

// TestEffectiveSignatures_Cap ensures operator signatures past the slot budget
// are dropped (not silently overwriting built-ins).
func TestEffectiveSignatures_Cap(t *testing.T) {
	store := NewMemNetworkPolicySignatureStore()
	ctx := context.Background()
	// Add more than the budget worth of operator signatures.
	for i := 0; i < netbpf.SigMaxCount+5; i++ {
		name := "op-" + string(rune('a'+i%26)) + string(rune('0'+i/26))
		if _, err := store.Set(ctx, name, []byte("X"), true, ""); err != nil {
			t.Fatal(err)
		}
	}
	e := &NetworkPolicyEnforcer{sigStore: store, ctx: ctx}
	sigs, _ := e.effectiveSignatures()
	if len(sigs) > netbpf.SigMaxCount {
		t.Fatalf("merged set %d exceeds slot budget %d", len(sigs), netbpf.SigMaxCount)
	}
	// Built-ins must survive the cap (they're added first).
	if sigs[0].ID != netpolicy.BuiltinSignatures()[0].ID {
		t.Error("built-ins should not be evicted by the cap")
	}
}
