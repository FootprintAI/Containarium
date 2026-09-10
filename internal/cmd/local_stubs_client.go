//go:build containarium_client

package cmd

import (
	"errors"

	"github.com/footprintai/containarium/internal/client"
	"github.com/footprintai/containarium/pkg/core/incus"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// errNoLocalMode is what every stub below returns. The containarium client
// has no local-Incus code path at all (see
// docs/architecture/cli-client-server-split.md) — this is the message a
// user sees if they somehow reach one of these stubs (in practice,
// resolveServerAddr's server-resolution chain and the "no server
// configured" error at the client constructors already fail earlier for
// every one of the thirteen hybrid commands (#1785 added collaborator as
// the thirteenth); these stubs are defence in
// depth, turning a future forgotten check into a clear error instead of a
// build break or a silent local Incus call).
var errNoLocalMode = errors.New("this is the containarium client; it has no local mode — pass --server, run `containarium login`, or use containariumd on the host")

// create.go
func containerExistsLocal(_ string) (bool, error) { return false, errNoLocalMode }
func createJumpServerAccountLocal(_, _ string, _ bool) error {
	return errNoLocalMode
}
func cleanupJumpServerAccountLocal(_ string) {}
func createLocal(_, _, _, _, _, _ string, _ []string, _ map[string]string, _ bool, _ string, _ []string, _ pb.OSType, _ bool, _ client.GitSourceOpts, _ int64, _ int32, _ int64, _ string) (*incus.ContainerInfo, error) {
	return nil, errNoLocalMode
}

// delete.go
func deleteLocal(_ string, _ bool) error            { return errNoLocalMode }
func deleteJumpServerAccountLocal(_ string, _ bool) {}

// get.go
func getLocal(_ string) (*incus.ContainerInfo, error) { return nil, errNoLocalMode }

// list.go
func listLocal() ([]incus.ContainerInfo, error) { return nil, errNoLocalMode }

// info.go — "the two info helpers"
func getSystemInfoLocal() (*incus.ServerInfo, []incus.ContainerInfo, error) {
	return nil, nil, errNoLocalMode
}
func getContainerInfoLocal(_ string) (*incus.ContainerInfo, error) { return nil, errNoLocalMode }

// label_list.go / label_set.go / label_remove.go
func getLabelsLocal(_ string) (map[string]string, error) { return nil, errNoLocalMode }
func setLabelsLocal(_ string, _ map[string]string) error { return errNoLocalMode }
func removeLabelsLocal(_ string, _ []string) error       { return errNoLocalMode }

// install_stack.go
func installStackLocal(_, _ string) error { return errNoLocalMode }

// resize.go
func runResizeLocal(_, _ string) error { return errNoLocalMode }

// collaborator_add.go / collaborator_remove.go / collaborator_list.go
func addCollaboratorLocal(_, _ string, _ []string) error { return errNoLocalMode }
func removeCollaboratorLocal(_, _ string) error          { return errNoLocalMode }
func listCollaboratorsLocal(_ string) ([]collaboratorRow, error) {
	return nil, errNoLocalMode
}
