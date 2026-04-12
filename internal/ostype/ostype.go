package ostype

import (
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// OSFamily represents the OS family for provisioning decisions.
type OSFamily string

const (
	Debian OSFamily = "debian"
	RHEL   OSFamily = "rhel"
)

// OSTypeLabelKey is the Incus label key used to store the OS type.
const OSTypeLabelKey = "os-type"

// ImageForOSType returns the Incus image string for the given OS type.
func ImageForOSType(osType pb.OSType) string {
	switch osType {
	case pb.OSType_OS_TYPE_UBUNTU_2404:
		return "images:ubuntu/24.04"
	case pb.OSType_OS_TYPE_ROCKY_9:
		return "images:rockylinux/9"
	case pb.OSType_OS_TYPE_RHEL_9:
		return "local:rhel9"
	default:
		return "images:ubuntu/24.04"
	}
}

// FamilyForOSType returns the OS family for the given OS type.
func FamilyForOSType(osType pb.OSType) OSFamily {
	switch osType {
	case pb.OSType_OS_TYPE_ROCKY_9, pb.OSType_OS_TYPE_RHEL_9:
		return RHEL
	default:
		return Debian
	}
}

// LabelValue returns the string label value for storing in container metadata.
func LabelValue(osType pb.OSType) string {
	switch osType {
	case pb.OSType_OS_TYPE_UBUNTU_2404:
		return "ubuntu_2404"
	case pb.OSType_OS_TYPE_ROCKY_9:
		return "rocky_9"
	case pb.OSType_OS_TYPE_RHEL_9:
		return "rhel_9"
	default:
		return "ubuntu_2404"
	}
}

// FamilyFromLabel returns the OS family from a stored label value.
func FamilyFromLabel(label string) OSFamily {
	switch label {
	case "rocky_9", "rhel_9":
		return RHEL
	default:
		return Debian
	}
}

// OSTypeFromLabel returns the OSType enum from a stored label value.
func OSTypeFromLabel(label string) pb.OSType {
	switch label {
	case "ubuntu_2404":
		return pb.OSType_OS_TYPE_UBUNTU_2404
	case "rocky_9":
		return pb.OSType_OS_TYPE_ROCKY_9
	case "rhel_9":
		return pb.OSType_OS_TYPE_RHEL_9
	default:
		return pb.OSType_OS_TYPE_UBUNTU_2404
	}
}

// OSTypeFromString parses a CLI-friendly string into an OSType enum.
func OSTypeFromString(s string) pb.OSType {
	switch s {
	case "ubuntu", "ubuntu2404", "ubuntu-2404":
		return pb.OSType_OS_TYPE_UBUNTU_2404
	case "rocky9", "rocky-9", "rockylinux9":
		return pb.OSType_OS_TYPE_ROCKY_9
	case "rhel9", "rhel-9", "redhat9":
		return pb.OSType_OS_TYPE_RHEL_9
	default:
		return pb.OSType_OS_TYPE_UNSPECIFIED
	}
}

// Execer is the interface for executing commands in a container.
type Execer interface {
	Exec(containerName string, command []string) error
}

// DetectFamily probes a running container to determine its OS family.
// Used for InstallStack on containers where the os-type label is missing.
func DetectFamily(execer Execer, containerName string) OSFamily {
	if err := execer.Exec(containerName, []string{"test", "-f", "/etc/redhat-release"}); err == nil {
		return RHEL
	}
	return Debian
}
