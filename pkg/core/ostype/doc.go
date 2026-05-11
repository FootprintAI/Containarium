// Package ostype detects the OS family of a container (Debian, RHEL, etc.)
// and maps Containarium's logical OSType to concrete Incus image names.
// Used by the container Manager during Create to resolve the right image.
package ostype
