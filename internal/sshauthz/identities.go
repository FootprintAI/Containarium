package sshauthz

import (
	"sort"
	"sync"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// ManagedIdentities records, for each managed AuthorizeSSH ALLOW, which
// control-plane user id the cloud named for a (credential, local login)
// pair (#2602). A managed TERMINATE_USER_SESSIONS assignment carries that
// control-plane id, not a host-local username; the terminate handler
// resolves it to local logins through this record.
//
// Only ALLOW decisions are recorded: a denial's user id names who tried,
// not whose login it is, and mapping it would let one user's deactivation
// end another user's sessions. A later ALLOW for the same pair replaces the
// earlier owner. The record is in memory: after a daemon restart a user is
// mappable again from their next login.
type ManagedIdentities struct {
	mu     sync.RWMutex
	owners map[identityKey]string // (credential, login) -> control-plane user id
}

type identityKey struct {
	credential string // public-key fingerprint, or "cert:<ca fingerprint>:<key id>"
	login      string
}

// NewManagedIdentities returns an empty record.
func NewManagedIdentities() *ManagedIdentities {
	return &ManagedIdentities{owners: map[identityKey]string{}}
}

// recordDecision stores the (credential, user id, login) triple of an ALLOW
// that names a user. A nil record ignores it.
func (m *ManagedIdentities) recordDecision(req *pb.AuthorizeSSHRequest, resp *pb.AuthorizeSSHResponse) {
	if m == nil || resp.GetDecision() != pb.SSHAuthzDecision_SSH_AUTHZ_DECISION_ALLOW {
		return
	}
	userID, login := resp.GetUserId(), req.GetLogin()
	if userID == "" || login == "" {
		return
	}
	key := identityKey{credential: credentialID(req.GetCredential()), login: login}
	m.mu.Lock()
	m.owners[key] = userID
	m.mu.Unlock()
}

// Logins returns the local logins recorded for a control-plane user id,
// sorted and without duplicates; nil when none (or for a nil record).
func (m *ManagedIdentities) Logins(userID string) []string {
	if m == nil {
		return nil
	}
	m.mu.RLock()
	seen := map[string]bool{}
	for k, owner := range m.owners {
		if owner == userID {
			seen[k.login] = true
		}
	}
	m.mu.RUnlock()
	if len(seen) == 0 {
		return nil
	}
	out := make([]string, 0, len(seen))
	for l := range seen {
		out = append(out, l)
	}
	sort.Strings(out)
	return out
}

func credentialID(c *pb.SSHCredential) string {
	if cert := c.GetCertificate(); cert != nil {
		return "cert:" + cert.GetCaFingerprintSha256() + ":" + cert.GetKeyId()
	}
	return c.GetPublicKey().GetFingerprintSha256()
}
