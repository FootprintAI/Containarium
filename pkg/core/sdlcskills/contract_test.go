package sdlcskills

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

// The set ids of the contract are what a daemon accepts by name. They are
// written out here on purpose: changing the contract must change this test.
func TestKnownSetIDs_AreTheContractV1Ids(t *testing.T) {
	if ContractVersion != 1 {
		t.Fatalf("ContractVersion = %d; update this test with the new contract's ids", ContractVersion)
	}
	if got, want := KnownSetIDs(), []string{"qa", "sdlc", "security"}; !reflect.DeepEqual(got, want) {
		t.Errorf("KnownSetIDs() = %v, want %v", got, want)
	}
	// The caller cannot change the contract through the returned slice.
	KnownSetIDs()[0] = "changed"
	if KnownSetIDs()[0] != "qa" {
		t.Error("KnownSetIDs returned its backing slice")
	}
}

func TestValidateSetIDs(t *testing.T) {
	if err := ValidateSetIDs([]string{"sdlc", "qa", "security"}); err != nil {
		t.Errorf("known ids refused: %v", err)
	}
	if err := ValidateSetIDs(nil); err != nil {
		t.Errorf("empty list refused: %v", err)
	}
	for _, id := range []string{"data", "", "all", "none", "SDLC", "sdlc;rm"} {
		err := ValidateSetIDs([]string{"sdlc", id})
		var unknown *UnknownSetError
		if !errors.As(err, &unknown) {
			t.Errorf("%q: err = %v, want *UnknownSetError", id, err)
			continue
		}
		if unknown.ID != id {
			t.Errorf("%q: UnknownSetError.ID = %q", id, unknown.ID)
		}
		if !strings.Contains(err.Error(), "known skill sets: qa, sdlc, security") {
			t.Errorf("%q: message %q does not name the known ids", id, err)
		}
	}
}

func TestCheckContract(t *testing.T) {
	if err := CheckContract(ContractVersion); err != nil {
		t.Errorf("own contract refused: %v", err)
	}
	err := CheckContract(ContractVersion + 1)
	var tooNew *ContractTooNewError
	if !errors.As(err, &tooNew) {
		t.Fatalf("err = %v, want *ContractTooNewError", err)
	}
	if tooNew.Got != ContractVersion+1 || tooNew.Supported != ContractVersion {
		t.Errorf("ContractTooNewError = %+v", tooNew)
	}
	if !strings.Contains(err.Error(), "contract 2") || !strings.Contains(err.Error(), "supports contract 1") {
		t.Errorf("message %q does not name both contracts", err)
	}
	if err := CheckContract(0); err == nil {
		t.Error("contract 0 accepted")
	}
}
