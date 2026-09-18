package server

import (
	"strings"

	"github.com/footprintai/containarium/internal/collaborator"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// collaboratorToProto maps a stored collaborator row onto its wire type.
// #1144: SSHPublicKey may be several `authorized_keys` lines newline-joined
// (#369's AddCollaborator writes strings.Join(keys, "\n") into the one TEXT
// column) — this splits that back into ssh_public_keys and narrows the
// deprecated ssh_public_key scalar to a REAL single key (the first one)
// instead of silently returning the whole blob as "a key".
func collaboratorToProto(c *collaborator.Collaborator) *pb.Collaborator {
	keys := splitSSHPublicKeys(c.SSHPublicKey)
	first := c.SSHPublicKey
	if len(keys) > 0 {
		first = keys[0]
	}
	return &pb.Collaborator{
		Id:                   c.ID,
		ContainerName:        c.ContainerName,
		OwnerUsername:        c.OwnerUsername,
		CollaboratorUsername: c.CollaboratorUsername,
		AccountName:          c.AccountName,
		SshPublicKey:         first,
		SshPublicKeys:        keys,
		AddedAt:              c.CreatedAt.Unix(),
		CreatedBy:            c.CreatedBy,
		HasSudo:              c.HasSudo,
		HasContainerRuntime:  c.HasContainerRuntime,
	}
}

// splitSSHPublicKeys recovers the individual keys from the stored blob.
// Blank lines are dropped rather than round-tripped, since a blank
// "authorized key" is never authorizable — carrying it through as an
// empty-string list element would just move the encoding bug's residue into
// the very field meant to remove it.
func splitSSHPublicKeys(blob string) []string {
	if strings.TrimSpace(blob) == "" {
		return nil
	}
	parts := strings.Split(blob, "\n")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
