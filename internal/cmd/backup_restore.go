package cmd

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"strings"

	"github.com/footprintai/containarium/pkg/core/secrets"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/spf13/cobra"
)

var (
	backupRestoreClean    bool
	backupRestoreDatabase string
	backupRestoreDBUser   string
	backupRestoreDBPass   string
	backupRestoreDBHost   string
	backupRestoreDBPort   int32

	// #1831: path to the age identity file for an encrypted record.
	backupRestoreAgeIdentityFile string

	// #2403: managed key, newest-record selection, and restore target.
	backupRestoreManaged bool
	backupRestoreLatest  bool
	backupRestoreUser    string
	backupRestoreTarget  string
)

var backupRestoreCmd = &cobra.Command{
	Use:   "restore [<id>]",
	Short: "Restore a stored dump back into its container's database",
	Long: `Stream a stored dump back into the owning tenant's container database
via pg_restore. The dump is integrity-checked (SHA-256) before it touches
the database.

DESTRUCTIVE with --clean: pg_restore is run with --clean --if-exists,
dropping objects before recreating them. Without --clean, restore loads
into the existing database and errors on conflicting objects.

By default the dump is restored into the database it was taken from;
override with --database to restore into a different one. By default it
is restored into the backup's own container; --target <name>-container
restores into another tenant container instead (you must be authorized
for that tenant too).

Name the backup by id, or pass --latest with --user and --database to
restore the newest backup of that tenant's database.

An encrypted backup (created with --age-recipient) needs the matching age
identity: pass the key file with --age-identity-file. The platform holds
no decryption key, so a restore without it is refused. The identity is
read from the file (never argv), used for this one call, and not stored.

` + managedHelp + `

A hook backup (engine "hook") with the default opaque format is a stream
the platform never understood and cannot restore: fetch the object and
apply it with the tenant's tooling. A hook declared --hook-format
pg_custom can be restored, but only into a --target other than its
source container.

Examples:
  containarium backup restore alice-app-20260605T130405Z --clean --server <host>
  containarium backup restore alice-app-20260605T130405Z --database app_staging --server <host>
  containarium backup restore alice-app-20260605T130405Z --age-identity-file backup.key --clean --server <host>
  containarium backup restore --managed --latest --user alice --database app \
      --target scratch-container --server <host>`,
	Args: cobra.MaximumNArgs(1),
	RunE: runBackupRestore,
}

func init() {
	backupCmd.AddCommand(backupRestoreCmd)
	f := backupRestoreCmd.Flags()
	f.BoolVar(&backupRestoreClean, "clean", false, "pass --clean --if-exists to pg_restore (drops objects first)")
	f.StringVar(&backupRestoreDatabase, "database", "", "target database (default: the backup's own database)")
	f.StringVar(&backupRestoreDBUser, "db-user", "", "Postgres role (default: postgres)")
	f.StringVar(&backupRestoreDBPass, "db-password", "", "Postgres password (omit for peer/trust auth)")
	f.StringVar(&backupRestoreDBHost, "db-host", "", "DB host as seen inside the container (default: 127.0.0.1)")
	f.Int32Var(&backupRestoreDBPort, "db-port", 0, "DB port (default: 5432)")
	f.StringVar(&backupRestoreAgeIdentityFile, "age-identity-file", "", "age identity file (AGE-SECRET-KEY-1...) that decrypts an encrypted backup; required for records created with --age-recipient")
	f.BoolVar(&backupRestoreManaged, "managed", false, "unwrap the record's managed key with your own cloud credentials (audited by the KMS) instead of --age-identity-file")
	f.BoolVar(&backupRestoreLatest, "latest", false, "restore the newest backup for --user and --database instead of a named id")
	f.StringVar(&backupRestoreUser, "user", "", "tenant whose newest backup --latest selects")
	f.StringVar(&backupRestoreTarget, "target", "", "container to restore into, <username>-container (default: the backup's own container)")
}

// parseAgeIdentity extracts the single AGE-SECRET-KEY-1… line from an
// identity file as written by `age-keygen` (comment lines start with #).
// Exactly one identity is required: zero cannot decrypt anything and two
// would make it a guess which one was meant.
func parseAgeIdentity(content []byte) (string, error) {
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
		return "", fmt.Errorf("age identity file contains no identity (expected one AGE-SECRET-KEY-1... line)")
	case 1:
		return keys[0], nil
	default:
		return "", fmt.Errorf("age identity file contains %d identities; expected exactly one", len(keys))
	}
}

func runBackupRestore(cmd *cobra.Command, args []string) error {
	sel := backupSelection{
		args: args, latest: backupRestoreLatest, user: backupRestoreUser, database: backupRestoreDatabase,
		managed: backupRestoreManaged, ageIdentityFile: backupRestoreAgeIdentityFile,
	}
	if err := sel.validate(); err != nil {
		return err
	}
	// Read the identity before dialing: a missing key file is a local
	// mistake and should fail fast, without a round trip.
	var ageIdentity string
	if backupRestoreAgeIdentityFile != "" {
		content, err := os.ReadFile(backupRestoreAgeIdentityFile) // #nosec G304 -- operator-named identity file, read on the operator's own machine
		if err != nil {
			return fmt.Errorf("read age identity file: %w", err)
		}
		ageIdentity, err = parseAgeIdentity(content)
		if err != nil {
			return fmt.Errorf("%s: %w", backupRestoreAgeIdentityFile, err)
		}
	}
	if backupRestoreAgeIdentityFile != "" || backupRestoreManaged {
		if err := requireSecureTransportForIdentity(serverAddr, httpMode, insecure); err != nil {
			return err
		}
	}

	c, err := newBackupClientFn()
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()

	rec, err := sel.resolve(c)
	if err != nil {
		return err
	}
	if backupRestoreManaged {
		// Unwrapped here, under the operator's credentials; a KMS refusal
		// returns before the restore RPC. The buffer is zeroed once the
		// request is sent; the string copy in the request is dropped with it.
		secret, err := unwrapManagedIdentity(cmd.Context(), rec)
		if err != nil {
			return err
		}
		defer secrets.ZeroBytes(secret)
		ageIdentity = string(secret)
	}

	fmt.Printf("Restoring backup %q (clean=%t)...\n", rec.Id, backupRestoreClean)
	resp, err := c.RestoreBackup(&pb.RestoreBackupRequest{
		Id:              rec.Id,
		Clean:           backupRestoreClean,
		AgeIdentity:     ageIdentity,
		TargetContainer: backupRestoreTarget,
		Connection: &pb.PgConnection{
			Database: backupRestoreDatabase,
			User:     backupRestoreDBUser,
			Password: backupRestoreDBPass,
			Host:     backupRestoreDBHost,
			Port:     backupRestoreDBPort,
		},
	})
	if err != nil {
		return err
	}
	fmt.Printf("\n✓ %s\n", resp.Message)
	return nil
}
