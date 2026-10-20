package cluster

import (
	"os"
	"testing"

	"github.com/footprintai/containarium/internal/testsupport/postgres"
)

func TestMain(m *testing.M) {
	os.Exit(postgres.Run(m.Run))
}
