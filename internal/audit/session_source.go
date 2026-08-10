package audit

import (
	"context"
	"strings"
	"time"

	"github.com/footprintai/containarium/pkg/core/incus"
)

// Backend-neutral session collection (#1189).
//
// The collector's own job is scheduling, de-duplication and writing audit
// entries — none of which is backend-specific. What IS backend-specific is
// three things that travel together, and the interface groups them for that
// reason rather than for tidiness:
//
//   - which boxes to read
//   - how to read a box's session log
//   - how to parse a line of it
//
// They cannot be mixed and matched. Reading incus's /var/log/auth.log and
// parsing it with the dropbear patterns yields nothing; reading a K8s pod's
// log and parsing it as sshd yields nothing. Both failures are silent — an
// empty result reads exactly like a box nobody logged into — so the pairing
// belongs in one type where it cannot be split by accident.

// SessionBox is a box the collector should read sessions from.
type SessionBox struct {
	// Name is the backend's own identifier, recorded as the audit
	// ResourceID.
	Name string
	// Username is the tenant the box belongs to.
	Username string
	// Ref is a handle private to the source that produced this box — a pod
	// reference, say. Opaque to the collector, which only ever hands it back
	// to the same source; a backend whose Name is enough to locate the box
	// leaves it empty.
	Ref string
}

// SessionSource supplies session-log lines for one backend.
type SessionSource interface {
	// Boxes returns the running boxes whose sessions should be collected.
	Boxes(ctx context.Context) ([]SessionBox, error)
	// ReadSessions returns raw session-log text for a box.
	ReadSessions(ctx context.Context, box SessionBox) (string, error)
	// ParseLine extracts a successful login from a single line. fallback is
	// used when the line carries no timestamp of its own.
	ParseLine(line string, year int, fallback time.Time) (ts time.Time, user, source, method string, ok bool)
}

// --- incus -----------------------------------------------------------

// incusSessionSource reads OpenSSH's auth.log out of an incus container.
type incusSessionSource struct {
	client *incus.Client
}

// NewIncusSessionSource returns the LXC session source.
func NewIncusSessionSource(client *incus.Client) SessionSource {
	return &incusSessionSource{client: client}
}

func (s *incusSessionSource) Boxes(context.Context) ([]SessionBox, error) {
	containers, err := s.client.ListContainers()
	if err != nil {
		return nil, err
	}
	var boxes []SessionBox
	for _, c := range containers {
		if c.State != "Running" || c.Role.IsCoreRole() {
			continue
		}
		username := c.Name
		if strings.HasSuffix(c.Name, "-container") {
			username = strings.TrimSuffix(c.Name, "-container")
		}
		boxes = append(boxes, SessionBox{Name: c.Name, Username: username})
	}
	return boxes, nil
}

func (s *incusSessionSource) ReadSessions(_ context.Context, box SessionBox) (string, error) {
	stdout, _, err := s.client.ExecWithOutput(box.Name, []string{
		"grep", "Accepted", "/var/log/auth.log",
	})
	if err != nil {
		// grep exits 1 when there are no matches, which is not an error.
		if strings.Contains(err.Error(), "exited with code 1") {
			return "", nil
		}
		return "", err
	}
	return stdout, nil
}

func (s *incusSessionSource) ParseLine(line string, year int, _ time.Time) (time.Time, string, string, string, bool) {
	return parseAuthLogLine(line, year)
}
