package ospkg

import (
	"github.com/footprintai/containarium/pkg/core/ostype"
)

// PackageManager abstracts OS-specific package management and user operations.
type PackageManager interface {
	// UpdateCmd returns the command to update package repo metadata.
	UpdateCmd() []string

	// InstallCmd returns the command to install the given packages.
	InstallCmd(pkgs []string) []string

	// CreateUserCmd returns the command to create a user with a home directory.
	CreateUserCmd(username, gecos string) []string

	// SudoGroup returns the group name that grants sudo privileges.
	SudoGroup() string

	// SSHServiceName returns the systemd service name for SSH.
	SSHServiceName() string

	// BasePackages returns the base packages to install in every container.
	BasePackages() []string

	// PodmanAvailableInBaseRepos returns true if podman is in the distro's base repos.
	PodmanAvailableInBaseRepos() bool

	// PodmanRepoScript returns a bash script to add the Podman repo (empty if not needed).
	PodmanRepoScript() string

	// PipInstallCmd returns the command to install pip.
	PipInstallCmd() []string

	// CleanCmd returns the command to clean package caches.
	CleanCmd() []string
}

// ForFamily returns the appropriate PackageManager for the given OS family.
// Panics for Windows — Windows VMs do not use Linux package managers.
func ForFamily(family ostype.OSFamily) PackageManager {
	switch family {
	case ostype.RHEL:
		return &rhelPkgMgr{}
	case ostype.Windows:
		panic("ospkg.ForFamily called with Windows family — Windows VMs skip Linux package installation")
	default:
		return &debianPkgMgr{}
	}
}
