package config

import "time"

// EnvSSHDPostureDisable turns off the box sshd posture reconciler (#2424),
// which otherwise runs on every backend: it needs only the incus file API,
// no Postgres and no eBPF. Findings it raises ride the threat-detection
// sentry's store when that is up; otherwise they are logged.
const EnvSSHDPostureDisable = "CONTAINARIUM_SSHD_POSTURE_DISABLE"

// EnvSSHDPostureIntervalMinutes overrides how often the reconciler
// re-reads every running box's sshd configuration and re-asserts the
// managed key-only drop-in. Zero/unset uses
// security.DefaultSSHDPostureInterval.
const EnvSSHDPostureIntervalMinutes = "CONTAINARIUM_SSHD_POSTURE_INTERVAL_MINUTES"

// SSHDPosture is the typed view of the CONTAINARIUM_SSHD_POSTURE_* namespace.
type SSHDPosture struct {
	Disabled bool
	// Interval is zero when the operator set no override.
	Interval time.Duration
}

// LoadSSHDPosture reads the CONTAINARIUM_SSHD_POSTURE_* namespace once.
func LoadSSHDPosture() SSHDPosture {
	return SSHDPosture{
		Disabled: getBool(EnvSSHDPostureDisable),
		Interval: time.Duration(getInt(EnvSSHDPostureIntervalMinutes, 0)) * time.Minute,
	}
}
