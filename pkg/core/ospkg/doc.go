// Package ospkg abstracts over Linux package managers (apt on Debian /
// Ubuntu, dnf on RHEL / Fedora) so installer logic can target a single
// PackageManager interface regardless of the container's OS family.
package ospkg
