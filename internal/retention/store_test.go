package retention_test

import (
	"testing"

	"github.com/footprintai/containarium/internal/retention"
	"github.com/footprintai/containarium/internal/retention/storetest"
)

func TestMemoryStoreContract(t *testing.T) {
	storetest.RunStoreContract(t, func(*testing.T) retention.Store { return retention.NewMemoryStore() })
}
