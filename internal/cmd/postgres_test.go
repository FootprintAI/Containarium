package cmd

import (
	"os"
	"testing"

	"github.com/footprintai/containarium/internal/testsupport/postgres"
)

func TestMain(m *testing.M) {
	cleanup := isolateCredentialStore()
	code := postgres.Run(m.Run)
	cleanup()
	os.Exit(code)
}
