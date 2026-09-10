//go:build !containarium_client

package cmd

import (
	"fmt"
	"time"

	"github.com/footprintai/containarium/internal/client"
	"github.com/footprintai/containarium/pkg/core/container"
	"github.com/footprintai/containarium/pkg/core/incus"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// containerExistsLocal is runCreate's --force existence check in local mode
// (Incus ContainerExists on the container's fully-qualified name).
func containerExistsLocal(username string) (bool, error) {
	mgr, err := container.New()
	if err != nil {
		return false, fmt.Errorf("failed to connect to Incus: %w", err)
	}
	containerName := username + "-container"
	return mgr.ContainerExists(containerName), nil
}

// createJumpServerAccountLocal creates the proxy-only SSH jump-server
// account for a new local-mode container. Only called when a key was
// provided (a keyless service tenant has no SSH path, so there's no jump
// account to seed).
func createJumpServerAccountLocal(username, sshKey string, verbose bool) error {
	if err := container.CreateJumpServerAccount(username, sshKey, verbose); err != nil {
		return fmt.Errorf("failed to create jump server account: %w\nNote: This command must be run with sudo/root privileges", err)
	}
	return nil
}

// cleanupJumpServerAccountLocal best-effort removes the jump-server account
// created by createJumpServerAccountLocal when the subsequent createLocal
// call fails. Mirrors the original inline `_ = container.DeleteJumpServerAccount(username, false)`.
func cleanupJumpServerAccountLocal(username string) {
	_ = container.DeleteJumpServerAccount(username, false)
}

// createLocal creates a container using local Incus daemon
func createLocal(username, image, cpu, memory, disk, staticIP string, sshKeys []string, labelMap map[string]string, enablePodman bool, stack string, gpus []string, osType pb.OSType, monitoring bool, git client.GitSourceOpts, ttlSeconds int64, idleStopMinutes int32, deleteAfterStoppedSeconds int64, _ string) (*incus.ContainerInfo, error) {
	mgr, err := container.New()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Incus: %w (is Incus running?)", err)
	}

	opts := container.CreateOptions{
		Username:               username,
		Image:                  image,
		CPU:                    cpu,
		Memory:                 memory,
		Disk:                   disk,
		GPUs:                   gpus,
		StaticIP:               staticIP,
		SSHKeys:                sshKeys,
		Labels:                 labelMap,
		EnablePodman:           enablePodman,
		EnablePodmanPrivileged: enablePodman, // Enable privileged mode for proper Podman-in-LXC
		AutoStart:              true,
		Verbose:                verbose,
		Stack:                  stack,
		OSType:                 osType,
		Monitoring:             monitoring,
		GitSource:              git.Source,
		GitRef:                 git.Ref,
		GitCredential:          git.Credential,
		WorkspacePath:          git.WorkspacePath,
	}

	info, err := mgr.Create(opts)
	if err != nil {
		return nil, err
	}

	// Birth TTL (#523), local path. The daemon's CreateContainer stamps this
	// server-side; in local Incus mode we stamp the same key+format directly
	// so the box is born with its death date (reaped by whichever daemon
	// manages this host's ttlsweeper). On failure delete the box rather than
	// leave an ephemeral box that would leak — default-dead (#522), matching
	// the server path.
	if ttlSeconds > 0 {
		expiresAt := time.Now().Add(time.Duration(ttlSeconds) * time.Second).UTC()
		if serr := mgr.SetConfig(info.Name, incus.TTLExpiresAtKey, expiresAt.Format(time.RFC3339)); serr != nil {
			_ = deleteLocal(username, true)
			return nil, fmt.Errorf("failed to set birth TTL on %s (box deleted to avoid a leak): %w", info.Name, serr)
		}
	}

	// Birth idle-stop (#524), local path. Mirror the daemon's best-effort
	// stamp: enable auto-sleep with the requested threshold so the box is
	// born with its idle→stop timer. Best-effort — auto-sleep is an
	// optimization, not a leak contract, so a failed stamp warns and the box
	// keeps running (unlike the TTL path, we do NOT delete the box).
	if idleStopMinutes > 0 {
		if serr := mgr.SetConfig(info.Name, incus.AutoSleepEnabledKey, "true"); serr != nil {
			fmt.Printf("warning: failed to enable birth auto-sleep on %s: %v (continuing; box has no idle-stop)\n", info.Name, serr)
		} else if serr := mgr.SetConfig(info.Name, incus.IdleThresholdMinutesKey, fmt.Sprintf("%d", idleStopMinutes)); serr != nil {
			fmt.Printf("warning: enabled auto-sleep on %s but failed to set idle threshold: %v\n", info.Name, serr)
		}
	}

	// Birth stopped→delete (#525), local path. Best-effort, same as the
	// server path — persist the window; the clock starts when the box stops.
	if deleteAfterStoppedSeconds > 0 {
		if serr := mgr.SetConfig(info.Name, incus.DeleteAfterStoppedSecondsKey, fmt.Sprintf("%d", deleteAfterStoppedSeconds)); serr != nil {
			fmt.Printf("warning: failed to set birth stopped→delete on %s: %v (continuing; box has no stopped→delete)\n", info.Name, serr)
		}
	}

	return info, nil
}
