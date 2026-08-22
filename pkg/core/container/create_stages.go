package container

import "time"

// CreateStage identifies one stage of Manager.Create for latency
// instrumentation. The values are the `stage` label on the
// containarium.container.create_stage_duration_seconds histogram, so
// renaming one is a dashboard-visible change.
//
// These stages exist because the create path had no per-stage measurement at
// all — the cost table in docs/architecture/two-digit-ms-sandbox-spawn.md was
// derived by reading the code, and Phase 0 of that note is replacing it with
// numbers from here.
type CreateStage string

const (
	// StageCreateInstance is incus.CreateContainer — image/ZFS clone plus the
	// instance record.
	StageCreateInstance CreateStage = "create_instance"
	// StageStartInstance is incus.StartContainer — the full guest boot.
	StageStartInstance CreateStage = "start_instance"
	// StageSetLabels is the SetLabels API round-trip.
	StageSetLabels CreateStage = "set_labels"
	// StageJumpAccount is the host-side jump-server account creation,
	// including authorizing any additional keys. Skipped when the create has
	// no SSH keys.
	StageJumpAccount CreateStage = "jump_account"
	// StageWaitNetwork is the DHCP/lease wait.
	StageWaitNetwork CreateStage = "wait_network"
	// StageInstallPackages is the in-guest package install. Skipped on the
	// baked-image fast path, so its histogram count also says how often
	// creates miss the bake.
	StageInstallPackages CreateStage = "install_packages"
	// StageCreateUser is the in-guest tenant user creation.
	StageCreateUser CreateStage = "create_user"
	// StageAddSSHKeys is the in-guest authorized_keys seeding. Skipped when
	// there are no keys to add.
	StageAddSSHKeys CreateStage = "add_ssh_keys"
	// StageGitSource is the optional git workspace provisioning.
	StageGitSource CreateStage = "git_source"
	// StageGetInfo is the final GetContainer lookup.
	StageGetInfo CreateStage = "get_info"
	// StageTotal is the whole Create call, recorded only on success so the
	// histogram reads as "latency of a successful create" rather than being
	// dragged down by fast failures. Per-stage observations, by contrast,
	// are recorded even when the stage errors — a WaitForNetwork that spends
	// its full timeout before failing is exactly the sample worth keeping.
	StageTotal CreateStage = "total"
)

// StageObserver receives the duration of each create stage. Implementations
// must be safe for concurrent use (creates can run in parallel) and cheap —
// it is called on the create path.
type StageObserver func(stage CreateStage, d time.Duration)

// SetStageObserver installs the per-stage latency observer. nil (the
// default) disables observation. Call before the Manager serves requests;
// the field is not synchronized against in-flight creates.
func (m *Manager) SetStageObserver(obs StageObserver) {
	m.observeStage = obs
}

// timed runs f and reports its duration to the stage observer, error or not.
func (m *Manager) timed(stage CreateStage, f func() error) error {
	if m.observeStage == nil {
		return f()
	}
	start := time.Now()
	err := f()
	m.observeStage(stage, time.Since(start))
	return err
}
