package cmd

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"strings"

	"github.com/footprintai/containarium/internal/client"
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

	// #3358: whole-box restore.
	backupRestoreBox    string
	backupRestoreBackup string
	backupRestoreAs     string
	backupRestoreForce  bool
)

// restoreBoxFn is the box restore the platform MCP tool restore_box_backup
// also calls (CLI-first, CLAUDE.md).
var restoreBoxFn = client.RestoreBoxBackupFromFile

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

Whole-box backups (#3358): --box <box> --backup <id> restores a backup
taken with 'backup create <box> --box' into a new box, named with --as
(default: <box>-restored). The backup must be a whole-box backup of <box>.
A box of that name that already exists is refused unless --force is given,
and --force replaces only a stopped box: a running box is always refused,
so stop it first. A whole-box backup is always encrypted, so
--age-identity-file is required. The identity is read from the file, never
from argv. The database flags (--clean, --database, --db-*, --target,
--latest, --user, --managed) do not apply. A non-admin token can restore
only into a box named for its own tenant, so the default <box>-restored
needs an admin token.

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
      --target scratch-container --server <host>
  containarium backup restore --box alice --backup alice-box-20261101T000000Z \
      --as alice-copy --age-identity-file box.key --server <host>`,
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
	f.StringVar(&backupRestoreBox, "box", "", "restore a whole-box backup of this box into a new box (with --backup and --age-identity-file)")
	f.StringVar(&backupRestoreBackup, "backup", "", "with --box: id of the whole-box backup to restore")
	f.StringVar(&backupRestoreAs, "as", "", "with --box: name of the box to restore into (default: <box>-restored)")
	f.BoolVar(&backupRestoreForce, "force", false, "with --box: replace an existing stopped box of that name; a running box is always refused")
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
	if backupRestoreBox != "" || backupRestoreBackup != "" || backupRestoreAs != "" || backupRestoreForce {
		return runBackupRestoreBox(args)
	}
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

// runBackupRestoreBox is `backup restore --box` (#3358). Every usage error
// comes before the identity file is read or anything is sent.
func runBackupRestoreBox(args []string) error {
	if backupRestoreBox == "" {
		return fmt.Errorf("--backup, --as and --force restore a whole-box backup: name the box with --box")
	}
	if len(args) > 0 {
		return fmt.Errorf("with --box, name the backup with --backup, not as an argument")
	}
	if backupRestoreBackup == "" {
		return fmt.Errorf("--box needs --backup <id>")
	}
	for _, f := range []struct {
		name string
		set  bool
	}{
		{"--clean", backupRestoreClean},
		{"--database", backupRestoreDatabase != ""},
		{"--db-user", backupRestoreDBUser != ""},
		{"--db-password", backupRestoreDBPass != ""},
		{"--db-host", backupRestoreDBHost != ""},
		{"--db-port", backupRestoreDBPort != 0},
		{"--target", backupRestoreTarget != ""},
		{"--latest", backupRestoreLatest},
		{"--user", backupRestoreUser != ""},
		{"--managed", backupRestoreManaged},
	} {
		if f.set {
			return fmt.Errorf("%s does not apply to a whole-box restore (--box)", f.name)
		}
	}
	if backupRestoreAgeIdentityFile == "" {
		return fmt.Errorf("--box needs --age-identity-file: a whole-box backup is always encrypted")
	}
	if err := requireSecureTransportForIdentity(serverAddr, httpMode, insecure); err != nil {
		return err
	}

	target := backupRestoreAs
	if target == "" {
		target = backupRestoreBox + "-restored"
	}
	fmt.Printf("Restoring whole-box backup %q into box %q (force=%t)...\n", backupRestoreBackup, target, backupRestoreForce)
	resp, err := restoreBoxFn(func() (client.BoxRestoreAPI, error) { return newBackupClientFn() }, client.BoxRestoreParams{
		Box:             backupRestoreBox,
		BackupID:        backupRestoreBackup,
		As:              backupRestoreAs,
		Force:           backupRestoreForce,
		AgeIdentityFile: backupRestoreAgeIdentityFile,
	})
	if err != nil {
		return err
	}
	fmt.Printf("\n✓ %s\n  box: %s (stopped)\n", resp.Message, resp.Box)
	return nil
}
