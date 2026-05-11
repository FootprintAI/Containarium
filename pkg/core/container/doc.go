// Package container provides the high-level container lifecycle Manager
// used by both the OSS daemon and any future cloud daemon: create, start,
// stop, delete, resize, label, plus jump-server SSH provisioning and
// collaborator-account management.
//
// Manager wraps an incus.Backend; production code uses container.New(),
// tests use container.NewWithBackend(mock).
package container
