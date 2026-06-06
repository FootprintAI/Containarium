package runner

import (
	"context"
	"fmt"

	"github.com/footprintai/containarium/pkg/core/incus"
)

// DaemonAPI is the minimal slice of a containarium client that
// BoxManager needs. Both internal/client.HTTPClient and
// internal/client.GRPCClient satisfy this (they expose the
// methods used here on slightly broader interfaces). Keeping the
// interface here means internal/runner doesn't import
// internal/client and so dodges the import cycle that would
// arise if internal/client wanted to call back into runner.
type DaemonAPI interface {
	ListContainers() ([]incus.ContainerInfo, error)
	GetContainer(username string) (*incus.ContainerInfo, error)
	DeleteContainer(username string, force bool) error
}

// DaemonCreator narrows down "the bit of the daemon client that
// makes a new container." Real implementations have richer
// signatures; we just need name + ssh key + a return of the box
// ID and the daemon-assigned SSH username. Done as a function shape
// so callers can curry their full create call (with all the
// labels/cpu/etc baked in) into something this package can drive.
//
// username is the login the daemon actually assigned to the box (which
// may differ from the requested name — a control plane can mint a
// generated username at create); it is what the daemon's SSH front
// routes by, so the install step must SSH as it, not as name. Empty when
// the daemon doesn't report one (then callers fall back to name).
type DaemonCreator func(ctx context.Context, name, sshKey string) (boxID, username string, err error)

// NewDaemonBoxManager wraps a (DaemonAPI, DaemonCreator) pair as
// a BoxManager. The split lets callers reuse their existing
// create-container plumbing (which has a wide signature with
// CPU/memory/disk/labels/etc) without forcing every caller
// through a one-size-fits-all interface.
func NewDaemonBoxManager(api DaemonAPI, create DaemonCreator) BoxManager {
	return &daemonBoxManager{api: api, create: create}
}

type daemonBoxManager struct {
	api    DaemonAPI
	create DaemonCreator
}

func (m *daemonBoxManager) Exists(_ context.Context, name string) (bool, string, error) {
	// The daemon's "name" for a user-container is
	// "<username>-container" — the create flow appends the
	// suffix server-side. We pass the raw user/runner name to
	// GetContainer which knows the convention.
	info, err := m.api.GetContainer(name)
	if err != nil {
		// Best-effort: distinguish "not found" from real
		// failures. The HTTP/gRPC clients both return errors
		// that include the daemon's response text, so we
		// substring-match "not found". A false negative here
		// (real error misread as not-found) sends us into
		// Create, which will surface the real error anyway.
		if isNotFoundError(err) {
			return false, "", nil
		}
		return false, "", err
	}
	// Return the daemon-assigned username so idempotent re-runs can
	// SSH as the same cld-<uuid> the box originally got, not the
	// friendly requested name. (#482)
	return true, info.Username, nil
}

func (m *daemonBoxManager) Create(ctx context.Context, name, sshKey string) (boxID, username string, err error) {
	return m.create(ctx, name, sshKey)
}

func (m *daemonBoxManager) Delete(_ context.Context, name string, force bool) error {
	return m.api.DeleteContainer(name, force)
}

func (m *daemonBoxManager) List(_ context.Context) ([]string, error) {
	containers, err := m.api.ListContainers()
	if err != nil {
		return nil, fmt.Errorf("list containers: %w", err)
	}
	names := make([]string, 0, len(containers))
	for _, c := range containers {
		// Container Name is "<username>-container"; strip the
		// suffix so caller-facing names match what they passed
		// at create time.
		name := c.Name
		const suffix = "-container"
		if len(name) > len(suffix) && name[len(name)-len(suffix):] == suffix {
			name = name[:len(name)-len(suffix)]
		}
		names = append(names, name)
	}
	return names, nil
}

// isNotFoundError is a substring-based discriminator over the
// daemon client error text. The HTTP client wraps the response
// body verbatim ("API error (status 404): …") and the gRPC
// client surfaces the same via status messages. We don't have a
// typed NotFound error in internal/client today; substring is
// the pragmatic choice and the failure mode (false negative →
// proceed to Create → real error surfaces) is benign.
func isNotFoundError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	for _, marker := range []string{"not found", "404", "NotFound", "does not exist"} {
		if containsCaseFold(msg, marker) {
			return true
		}
	}
	return false
}

// containsCaseFold is strings.Contains with case folding. Small
// enough to inline rather than import the strings package twice.
func containsCaseFold(s, substr string) bool {
	if len(substr) == 0 {
		return true
	}
	if len(s) < len(substr) {
		return false
	}
	ls := toLower(s)
	lsub := toLower(substr)
	for i := 0; i+len(lsub) <= len(ls); i++ {
		if ls[i:i+len(lsub)] == lsub {
			return true
		}
	}
	return false
}

func toLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}
