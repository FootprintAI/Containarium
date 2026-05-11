// Package incus wraps the Incus/LXC API used to drive container lifecycle,
// networking, and storage on a Containarium host. It exposes a concrete
// production *Client and a Backend interface that consumers depend on for
// mocking (see pkg/core/incus/incustest.MockBackend).
//
// Most consumers should depend on Backend, not *Client. Methods that exist
// only on *Client (not in Backend) tend to be daemon-shape helpers rather
// than reusable primitives.
package incus
