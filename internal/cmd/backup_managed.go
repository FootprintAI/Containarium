package cmd

import (
	"context"
	"fmt"

	"github.com/footprintai/containarium/internal/backupkey"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// managedKMSLoader builds the operator's own KMS client for --managed
// (#2403). Tests replace it with a fake.
var managedKMSLoader backupkey.KMSLoader = backupkey.LoadOperatorKMS

// managedHelp is the --managed paragraph shared by restore and verify.
const managedHelp = `A managed backup (created with --key-mode managed or both) carries its
own key, wrapped by the daemon's KMS key, which the daemon itself cannot
unwrap. With --managed this command fetches the record, unwraps that key
in THIS process using your own cloud credentials, and sends the identity
over the same TLS-only path as --age-identity-file. The decrypt is
audited by the KMS under your principal; a principal without the
decrypter role gets a permission error before any restore or verify call
reaches the host. Nothing is written to disk. On an operator machine:

  export CONTAINARIUM_KMS_BACKEND=gcp
  export CONTAINARIUM_GCP_KMS_TOKEN=$(gcloud auth print-access-token)`

// backupSelection is how a restore or verify names its record: a
// positional id, or --latest with --user and --database.
type backupSelection struct {
	args            []string
	latest          bool
	user, database  string
	managed         bool
	ageIdentityFile string
}

// validate refuses every combination that would leave the command
// guessing, before anything is dialed or unwrapped.
func (s backupSelection) validate() error {
	if s.managed && s.ageIdentityFile != "" {
		return fmt.Errorf("--managed and --age-identity-file are mutually exclusive: pick the key source")
	}
	if s.latest {
		if len(s.args) > 0 {
			return fmt.Errorf("--latest and a backup id are mutually exclusive")
		}
		if s.user == "" || s.database == "" {
			return fmt.Errorf("--latest needs --user and --database")
		}
		return nil
	}
	if len(s.args) != 1 {
		return fmt.Errorf("a backup id is required (or --latest with --user and --database)")
	}
	return nil
}

// resolve returns the record to act on. The record itself is only
// fetched when it is needed: for --latest, or to read a managed key.
func (s backupSelection) resolve(c backupAPI) (*pb.BackupRecord, error) {
	if s.latest {
		recs, err := c.ListBackups(s.user)
		if err != nil {
			return nil, err
		}
		return backupkey.Newest(recs, s.user, s.database)
	}
	if !s.managed {
		return &pb.BackupRecord{Id: s.args[0]}, nil
	}
	return c.GetBackup(s.args[0])
}

// unwrapManagedIdentity is the CLI's call into the shared unwrap. The
// caller zeroes the returned buffer after the request is sent.
func unwrapManagedIdentity(ctx context.Context, rec *pb.BackupRecord) ([]byte, error) {
	return backupkey.UnwrapIdentity(ctx, managedKMSLoader, rec)
}
