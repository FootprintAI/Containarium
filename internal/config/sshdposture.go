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

// EnvSSHListenerCheckDisable turns off only the rogue SSH listener probe
// (#2439), which costs one exec inside every running box per pass, while
// leaving the sshd drop-in reconciler (#2424) running.
const EnvSSHListenerCheckDisable = "CONTAINARIUM_SSH_LISTENER_CHECK_DISABLE"

// SSHDPosture is the typed view of the CONTAINARIUM_SSHD_POSTURE_* namespace.
type SSHDPosture struct {
	Disabled bool
	// ListenerCheckDisabled turns off the rogue SSH listener probe only.
	ListenerCheckDisabled bool
	// Interval is zero when the operator set no override.
	Interval time.Duration
}

// LoadSSHDPosture reads the CONTAINARIUM_SSHD_POSTURE_* namespace once.
func LoadSSHDPosture() SSHDPosture {
	return SSHDPosture{
		Disabled:              getBool(EnvSSHDPostureDisable),
		ListenerCheckDisabled: getBool(EnvSSHListenerCheckDisable),
		Interval:              time.Duration(getInt(EnvSSHDPostureIntervalMinutes, 0)) * time.Minute,
	}
}
