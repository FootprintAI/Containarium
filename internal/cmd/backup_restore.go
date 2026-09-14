package cmd

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"strings"

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
)

var backupRestoreCmd = &cobra.Command{
	Use:   "restore <id>",
	Short: "Restore a stored dump back into its container's database",
	Long: `Stream a stored dump back into the owning tenant's container database
via pg_restore. The dump is integrity-checked (SHA-256) before it touches
the database.

DESTRUCTIVE with --clean: pg_restore is run with --clean --if-exists,
dropping objects before recreating them. Without --clean, restore loads
into the existing database and errors on conflicting objects.

By default the dump is restored into the database it was taken from;
override with --database to restore into a different one.

An encrypted backup (created with --age-recipient) needs the matching age
identity: pass the key file with --age-identity-file. The platform holds
no decryption key, so a restore without it is refused. The identity is
read from the file (never argv), used for this one call, and not stored.

A hook backup (engine "hook") is an opaque stream and cannot be restored
by the platform: fetch the object and apply it with the tenant's tooling.

Examples:
  containarium backup restore alice-app-20260605T130405Z --clean --server <host>
  containarium backup restore alice-app-20260605T130405Z --database app_staging --server <host>
  containarium backup restore alice-app-20260605T130405Z --age-identity-file backup.key --clean --server <host>`,
	Args: cobra.ExactArgs(1),
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

	c, err := newBackupClientFn()
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()

	fmt.Printf("Restoring backup %q (clean=%t)...\n", args[0], backupRestoreClean)
	resp, err := c.RestoreBackup(&pb.RestoreBackupRequest{
		Id:          args[0],
		Clean:       backupRestoreClean,
		AgeIdentity: ageIdentity,
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
