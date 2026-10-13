package guardrailpolicy_test

import (
	"testing"

	"github.com/footprintai/containarium/internal/guardrailpolicy"
	"github.com/footprintai/containarium/internal/guardrailpolicy/storetest"
)

func TestMemoryStore_Contract(t *testing.T) {
	storetest.RunStoreContract(t, func(*testing.T) guardrailpolicy.Store { return guardrailpolicy.NewMemoryStore() })
}
