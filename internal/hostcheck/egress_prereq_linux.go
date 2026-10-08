//go:build linux

package hostcheck

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/features"
	"golang.org/x/sys/unix"
)

func defaultEgressPrereqProbes() egressPrereqProbes {
	return egressPrereqProbes{
		kernelRelease: func() (string, error) {
			var u unix.Utsname
			if err := unix.Uname(&u); err != nil {
				return "", err
			}
			return unix.ByteSliceToString(u.Release[:]), nil
		},
		cgroupV2: func() (bool, error) {
			var st unix.Statfs_t
			if err := unix.Statfs("/sys/fs/cgroup", &st); err != nil {
				return false, err
			}
			return st.Type == unix.CGROUP2_SUPER_MAGIC, nil
		},
		// Loads a minimal cgroup_skb program; ErrNotSupported is the kernel
		// saying no, anything else (EPERM without CAP_BPF) is "could not tell".
		cgroupSKB: func() error {
			err := features.HaveProgramType(ebpf.CGroupSKB)
			if errors.Is(err, ebpf.ErrNotSupported) {
				return fmt.Errorf("%w: %v", errCgroupSKBUnsupported, err)
			}
			return err
		},
	}
}
