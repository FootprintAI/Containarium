package server

import (
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// #3213: SystemInfo carries whether the daemon has a managed backup key, and
// defaults to false so an unwired daemon never claims encryption it lacks.
func TestSystemInfoManagedBackupKey(t *testing.T) {
	s := &ContainerServer{}
	info := &pb.SystemInfo{}
	s.withBackupKeyInfo(info)
	if info.ManagedBackupKeyConfigured {
		t.Error("default must be false")
	}
	s.SetManagedBackupKeyConfigured(true)
	s.withBackupKeyInfo(info)
	if !info.ManagedBackupKeyConfigured {
		t.Error("want true after SetManagedBackupKeyConfigured(true)")
	}
}
