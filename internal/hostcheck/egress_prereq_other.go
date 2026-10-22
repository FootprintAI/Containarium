//go:build !linux

package hostcheck

import "errors"

// The egress program is Linux-only; elsewhere every probe reports
// "could not determine", so the checks fail rather than pass.
func defaultEgressPrereqProbes() egressPrereqProbes {
	errNotLinux := errors.New("not a Linux host")
	return egressPrereqProbes{
		kernelRelease: func() (string, error) { return "", errNotLinux },
		cgroupV2:      func() (bool, error) { return false, errNotLinux },
		cgroupSKB:     func() error { return errNotLinux },
	}
}
