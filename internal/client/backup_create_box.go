package client

import (
	"errors"
	"strings"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// Whole-box backup (#2801, #3504): `containarium backup create --box` and the
// platform MCP tool create_backup with scope "box" both call CreateBoxBackup,
// so the two cannot drift.

// BoxBackupAPI is the slice of the typed client a box backup uses. Both the
// gRPC and the HTTP client satisfy it.
type BoxBackupAPI interface {
	CreateBackup(req *pb.CreateBackupRequest) (*pb.CreateBackupResponse, error)
	Close() error
}

var (
	_ BoxBackupAPI = (*GRPCClient)(nil)
	_ BoxBackupAPI = (*HTTPClient)(nil)
)

// BoxBackupParams are the inputs of a whole-box backup, as the CLI flags and
// the MCP tool arguments name them.
type BoxBackupParams struct {
	// Box is the tenant whose box ("<box>-container") is backed up.
	Box string
	// Destination is where the archive is stored.
	Destination pb.BackupDestination
	// GCSBucket is the bucket (and optional prefix) for a GCS destination.
	GCSBucket string
	// AgeRecipient encrypts to this age public key. Empty lets the daemon
	// use the recipient the tenant registered, if any.
	AgeRecipient string
	// KeyMode says who holds the key. It must be set: a whole-box backup is
	// never plaintext, so there is no daemon default to fall back on.
	KeyMode pb.BackupKeyMode
}

// CreateBoxBackup takes a whole-box backup. Local refusals (no box, no key
// mode, a GCS destination without a bucket) come before newAPI is called, so
// a refused call sends nothing. The
// request carries no database connection and no hook, which the daemon
// refuses on a BOX request.
func CreateBoxBackup(newAPI func() (BoxBackupAPI, error), p BoxBackupParams) (*pb.CreateBackupResponse, error) {
	switch {
	case strings.TrimSpace(p.Box) == "":
		return nil, errors.New("the box to back up is required")
	case p.KeyMode == pb.BackupKeyMode_BACKUP_KEY_MODE_UNSPECIFIED:
		return nil, errors.New("a whole-box backup needs a key mode (managed, both or age recipient): it is never plaintext")
	case p.Destination == pb.BackupDestination_BACKUP_DESTINATION_GCS && strings.TrimSpace(p.GCSBucket) == "":
		return nil, errors.New("a GCS destination needs a bucket")
	}

	api, err := newAPI()
	if err != nil {
		return nil, err
	}
	defer func() { _ = api.Close() }()

	return api.CreateBackup(&pb.CreateBackupRequest{
		Username:     p.Box,
		Scope:        pb.BackupScope_BACKUP_SCOPE_BOX,
		Destination:  p.Destination,
		GcsBucket:    p.GCSBucket,
		AgeRecipient: p.AgeRecipient,
		KeyMode:      p.KeyMode,
	})
}
