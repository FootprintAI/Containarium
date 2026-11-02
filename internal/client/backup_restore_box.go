package client

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// Whole-box restore (#3358): `containarium backup restore --box` and the
// platform MCP tool restore_box_backup both call RestoreBoxBackupFromFile,
// so the two cannot drift.

// BoxRestoreAPI is the slice of the typed client a box restore uses. Both
// the gRPC and the HTTP client satisfy it.
type BoxRestoreAPI interface {
	GetBackup(id string) (*pb.BackupRecord, error)
	RestoreBoxBackup(req *pb.RestoreBoxBackupRequest) (*pb.RestoreBoxBackupResponse, error)
	Close() error
}

var (
	_ BoxRestoreAPI = (*GRPCClient)(nil)
	_ BoxRestoreAPI = (*HTTPClient)(nil)
)

// BoxRestoreParams are the inputs of a box restore, as the CLI flags and
// the MCP tool arguments name them.
type BoxRestoreParams struct {
	// Box is the box the backup was taken of. The record must be a
	// whole-box backup of this box.
	Box string
	// BackupID names the backup.
	BackupID string
	// As is the box to restore into. Empty lets the daemon use its default,
	// "<box>-restored".
	As string
	// Force replaces a stopped box of that name. A running box is always
	// refused.
	Force bool
	// AgeIdentityFile is the path of the file holding the age identity that
	// opens the backup. The identity is read from the file, never from an
	// argument, sent for this one call, and never logged or put in an error.
	AgeIdentityFile string
}

// RestoreBoxBackupFromFile restores a whole-box backup into a box. Local
// refusals (missing inputs, an unreadable identity file) come before newAPI
// is called. The record is then checked to be a whole-box backup of
// p.Box before the identity is sent.
func RestoreBoxBackupFromFile(newAPI func() (BoxRestoreAPI, error), p BoxRestoreParams) (*pb.RestoreBoxBackupResponse, error) {
	switch {
	case strings.TrimSpace(p.Box) == "":
		return nil, errors.New("the box the backup was taken of is required")
	case strings.TrimSpace(p.BackupID) == "":
		return nil, errors.New("a backup id is required")
	case p.AgeIdentityFile == "":
		return nil, errors.New("an age identity file is required: a whole-box backup is always encrypted, and the platform holds no decryption key")
	}
	identity, err := ReadAgeIdentityFile(p.AgeIdentityFile)
	if err != nil {
		return nil, err
	}

	api, err := newAPI()
	if err != nil {
		return nil, err
	}
	defer func() { _ = api.Close() }()

	rec, err := api.GetBackup(p.BackupID)
	if err != nil {
		return nil, err
	}
	if rec.GetScope() != pb.BackupScope_BACKUP_SCOPE_BOX {
		return nil, fmt.Errorf("backup %s is not a whole-box backup: restore it without --box", p.BackupID)
	}
	if rec.GetUsername() != p.Box {
		return nil, fmt.Errorf("backup %s is a backup of box %s, not %s", p.BackupID, rec.GetUsername(), p.Box)
	}
	return api.RestoreBoxBackup(&pb.RestoreBoxBackupRequest{
		Id:          p.BackupID,
		TargetBox:   p.As,
		Force:       p.Force,
		AgeIdentity: identity,
	})
}

// ReadAgeIdentityFile reads the one AGE-SECRET-KEY-1... line of an identity
// file as age-keygen writes it (comment lines start with #). Exactly one is
// required: zero opens nothing, and with two it would be a guess which was
// meant. No error carries the file's content.
func ReadAgeIdentityFile(path string) (string, error) {
	content, err := os.ReadFile(path) // #nosec G304 -- operator-named identity file, read on the operator's own machine
	if err != nil {
		return "", fmt.Errorf("read age identity file: %w", err)
	}
	var keys []string
	sc := bufio.NewScanner(bytes.NewReader(content))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		keys = append(keys, line)
	}
	switch len(keys) {
	case 0:
		return "", fmt.Errorf("%s: age identity file contains no identity (expected one AGE-SECRET-KEY-1... line)", path)
	case 1:
		return keys[0], nil
	default:
		return "", fmt.Errorf("%s: age identity file contains %d identities; expected exactly one", path, len(keys))
	}
}
