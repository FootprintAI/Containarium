package container

import (
	"fmt"
	"regexp"
	"strings"
)

var (
	// containerNameRegex enforces alphanumeric + hyphens only
	containerNameRegex = regexp.MustCompile(`^[a-z0-9-]+$`)

	// ErrReservedPrefix is returned when container name starts with underscore
	ErrReservedPrefix = fmt.Errorf("container names starting with '_' are reserved for system use")

	// ErrInvalidFormat is returned when container name has invalid format
	ErrInvalidFormat = fmt.Errorf("container name must contain only lowercase letters, numbers, and hyphens")

	// ErrEmpty is returned when container name is empty
	ErrEmpty = fmt.Errorf("container name cannot be empty")

	// ErrTooLong is returned when container name exceeds maximum length
	ErrTooLong = fmt.Errorf("container name cannot exceed 63 characters")
)

const (
	// MaxContainerNameLength is the maximum allowed length for container names
	// This follows DNS label standards (RFC 1035)
	MaxContainerNameLength = 63

	// SystemContainerPrefix is the reserved prefix for system containers
	SystemContainerPrefix = "_"
)

// ValidateContainerName validates a container name according to Containarium rules.
//
// Rules:
// 1. Cannot start with underscore (_) - reserved for system containers
// 2. Must contain only lowercase letters, numbers, and hyphens
// 3. Cannot be empty
// 4. Cannot exceed 63 characters (DNS label limit)
//
// Examples:
//   - Valid: "alice", "bob-dev", "team-api-prod"
//   - Invalid: "_containarium-core", "Alice", "my_app", ""
func ValidateContainerName(name string) error {
	// Check if empty
	if name == "" {
		return ErrEmpty
	}

	// Check length
	if len(name) > MaxContainerNameLength {
		return fmt.Errorf("%w (got %d characters)", ErrTooLong, len(name))
	}

	// Check for reserved system prefix
	if strings.HasPrefix(name, SystemContainerPrefix) {
		return ErrReservedPrefix
	}

	// Check format (alphanumeric + hyphens only)
	if !containerNameRegex.MatchString(name) {
		return ErrInvalidFormat
	}

	return nil
}

// IsSystemContainer returns true if the container name is a system container
// (starts with underscore prefix).
func IsSystemContainer(name string) bool {
	return strings.HasPrefix(name, SystemContainerPrefix)
}

// ValidateUserContainerName validates a user-provided container name.
// This is an alias for ValidateContainerName with clearer naming.
func ValidateUserContainerName(name string) error {
	return ValidateContainerName(name)
}

// ValidateSystemContainerName validates a system container name.
// System containers MUST start with underscore prefix.
func ValidateSystemContainerName(name string) error {
	if name == "" {
		return ErrEmpty
	}

	if len(name) > MaxContainerNameLength {
		return fmt.Errorf("%w (got %d characters)", ErrTooLong, len(name))
	}

	// System containers MUST start with underscore
	if !strings.HasPrefix(name, SystemContainerPrefix) {
		return fmt.Errorf("system container names must start with '%s'", SystemContainerPrefix)
	}

	// Check format (alphanumeric + hyphens + underscore prefix)
	// Remove the underscore prefix and validate the rest
	nameWithoutPrefix := strings.TrimPrefix(name, SystemContainerPrefix)
	if !containerNameRegex.MatchString(nameWithoutPrefix) {
		return ErrInvalidFormat
	}

	return nil
}
