package server

import (
	"time"

	"github.com/footprintai/containarium/internal/hostaddr"
)

// The host-side box address resolution (#2618) lives in internal/hostaddr so
// the traffic cache can share it (#3690). These names keep the enforcer's call
// sites unchanged.

const defaultIncusLeaseDir = hostaddr.DefaultIncusLeaseDir

type (
	hostNIC     = hostaddr.NIC
	leaseReader = hostaddr.LeaseReader
)

func leaseDirFor(incusDataDir string) string { return hostaddr.LeaseDirFor(incusDataDir) }

func hostNICFor(config map[string]string, devices map[string]map[string]string) hostNIC {
	return hostaddr.NICFor(config, devices)
}

func newLeaseReader(dir string, now time.Time) *leaseReader { return hostaddr.NewLeaseReader(dir, now) }

func hostIPv4For(nic hostNIC, leases *leaseReader, guest [4]byte, hasGuest bool) ([4]byte, bool) {
	return hostaddr.IPv4For(nic, leases, guest, hasGuest)
}
