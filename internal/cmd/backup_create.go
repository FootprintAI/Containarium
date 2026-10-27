package cmd

import (
	"fmt"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/spf13/cobra"
)

var (
	backupCreateDatabase string
	backupCreateDest     string
	backupCreateBucket   string
	backupCreateDBUser   string
	backupCreateDBPass   string
	backupCreateDBHost   string
	backupCreateDBPort   int32

	// #1831
	backupCreateHook         string
	backupCreateLabel        string
	backupCreateAgeRecipient string

	// #2402
	backupCreateKeyMode string
	// #2405
	backupCreateHookFormat string
	// #2801
	backupCreateBox bool
)

var backupCreateCmd = &cobra.Command{
	Use:   "create <username>",
	Short: "Dump a container's database(s), or the whole box, and store them off-host",
	Long: `Run pg_dump inside the tenant's container and store the compressed
dump(s) at the chosen destination.

Omit --database to back up EVERY non-template database found in the
container — the default. This is usually what you want: no need to
already know a database name, and there's no name to get wrong. Pass
--database to dump just that one instead.

Connection defaults target a per-container local Postgres on loopback
(user "postgres", host 127.0.0.1, port 5432). The password, if needed, is
passed to pg_dump via PGPASSWORD inside the container — never on argv.

Credential-less hook mode (--hook): instead of pg_dump, run the tenant's
own program inside the container and capture its stdout as the dump. No
DB credential crosses to the platform, and databases the platform can't
reach directly (e.g. nested inside an in-container Docker stack) become
backup-able. The path must be absolute with no arguments. Hook dumps are
opaque by default: stored, listed and fetched, but never auto-restored.

If the hook emits a 'pg_dump -Fc' custom-format archive, say so with
--hook-format pg_custom. The backup can then be restore-tested with
'backup verify', and restored into a named target container other than
its source (never in place). This is a promise about the hook's output;
the daemon does not check it when the backup is taken.

User-held encryption (--age-recipient): encrypt the dump to an age public
key before it is staged or uploaded, so the daemon's disk, the object
store and the operator only ever hold ciphertext. Restore then needs the
matching identity (see 'backup restore --age-identity-file').

For a SCHEDULED backup, a tenant can register its recipient once instead
of passing --age-recipient on every run:
  containarium secrets set alice CONTAINARIUM_BACKUP_AGE_RECIPIENT age1...
A create with no --age-recipient flag then encrypts to that registered
key automatically; an explicit --age-recipient still overrides it for a
one-off call. Neither a tenant with no key registered nor a standalone
daemon (no secrets store) is an error — both mean plaintext, as today.

Managed keys (--key-mode): on a daemon configured with a backup KMS key
(CONTAINARIUM_BACKUP_KMS_KEY_NAME), each backup is encrypted to a fresh
per-backup identity whose secret is wrapped by the KMS and stored on the
record ('managed'); with a recipient as well, the same file also opens
with the tenant's own identity ('both'). The daemon can wrap but never
unwrap: restore and verify still take the identity from you, after you
unwrap it under your own KMS credentials. Omit the flag for the daemon
default (managed/both when a key is configured, otherwise as above);
'age-recipient' opts a single backup out of wrapping. A mode the daemon
cannot provide is refused, never silently downgraded.

Whole-box backup (--box): back up the tenant's entire box instead of a
database. The box is exported through Incus (on ZFS, from a point-in-time
snapshot Incus takes, so a running box is fine), the contents of /tmp,
/var/tmp, /var/cache and /run are left out, a manifest of file digests is
added, and the archive is encrypted before it is stored. A whole-box
backup is never plaintext: --key-mode is required. The database and hook
flags do not apply. The daemon caps a box backup at 256 GiB by default
(CONTAINARIUM_BACKUP_BOX_MAX_BYTES). The one limit applies to both the
box's uncompressed content and the stored archive. The daemon also checks
free space before starting.

Examples:
  containarium backup create alice --dest local --server <host>
  containarium backup create alice --box --key-mode managed --dest gcs \
      --gcs-bucket gs://my-backups/boxes --server <host>
  containarium backup create alice --database app --dest gcs \
      --gcs-bucket gs://my-backups/pg --db-password "$PGPW" --server <host>
  containarium backup create alice --hook /opt/backup/db-dump.sh --dest gcs \
      --gcs-bucket gs://my-backups/pg --server <host>
  containarium backup create alice --hook /opt/backup/pg-dump-fc.sh \
      --hook-format pg_custom --dest local --server <host>
  containarium backup create alice --database app --age-recipient age1... \
      --dest gcs --gcs-bucket gs://my-backups/pg --server <host>`,
	Args: cobra.ExactArgs(1),
	RunE: runBackupCreate,
}

func init() {
	backupCmd.AddCommand(backupCreateCmd)
	f := backupCreateCmd.Flags()
	f.StringVar(&backupCreateDatabase, "database", "", "database name to dump; omit to back up every non-template database found (default)")
	f.StringVar(&backupCreateDest, "dest", "local", "destination: 'local' or 'gcs'")
	f.StringVar(&backupCreateBucket, "gcs-bucket", "", "GCS bucket/prefix for --dest gcs, e.g. gs://my-backups/pg")
	f.StringVar(&backupCreateDBUser, "db-user", "", "Postgres role (default: postgres)")
	f.StringVar(&backupCreateDBPass, "db-password", "", "Postgres password (omit for peer/trust auth)")
	f.StringVar(&backupCreateDBHost, "db-host", "", "DB host as seen inside the container (default: 127.0.0.1)")
	f.Int32Var(&backupCreateDBPort, "db-port", 0, "DB port (default: 5432)")
	f.StringVar(&backupCreateHook, "hook", "", "absolute path of an in-container program whose stdout is the dump; bypasses pg_dump and --db-* (#1831)")
	f.StringVar(&backupCreateLabel, "label", "", "label for a --hook backup, used in the backup id (default: the hook's basename)")
	f.StringVar(&backupCreateHookFormat, "hook-format", "", "declared format of the --hook output: 'opaque' (default) or 'pg_custom' (a pg_dump -Fc archive, restore-testable)")
	f.StringVar(&backupCreateAgeRecipient, "age-recipient", "", "age public key (age1...) to encrypt the dump to before it is stored; restore needs the matching identity")
	f.BoolVar(&backupCreateBox, "box", false, "back up the whole box instead of a database; needs --key-mode (#2801)")
	f.StringVar(&backupCreateKeyMode, "key-mode", "", "who holds the key: 'managed' (KMS-wrapped per-backup key), 'both' (managed plus --age-recipient), 'age-recipient' (no wrapping); omit for the daemon default (#2402)")
}

func runBackupCreate(cmd *cobra.Command, args []string) error {
	username := args[0]
	dest, err := parseDestination(backupCreateDest)
	if err != nil {
		return err
	}
	if dest == pb.BackupDestination_BACKUP_DESTINATION_GCS && backupCreateBucket == "" {
		return fmt.Errorf("--gcs-bucket is required when --dest gcs")
	}
	keyMode, err := parseKeyMode(backupCreateKeyMode)
	if err != nil {
		return err
	}
	hookFormat, err := parseHookFormat(backupCreateHookFormat)
	if err != nil {
		return err
	}

	if backupCreateBox {
		return runBackupCreateBox(username, dest, keyMode)
	}

	c, err := newBackupClientFn()
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()

	switch {
	case backupCreateHook != "":
		fmt.Printf("Backing up %s via hook %s to %s...\n", username, backupCreateHook, backupCreateDest)
	case backupCreateDatabase == "":
		fmt.Printf("Backing up every database in %s to %s...\n", username, backupCreateDest)
	default:
		fmt.Printf("Backing up %s database %q to %s...\n", username, backupCreateDatabase, backupCreateDest)
	}
	if backupCreateAgeRecipient != "" {
		fmt.Printf("Encrypting to %s (keep the matching identity off the platform; restore needs it)\n", backupCreateAgeRecipient)
	}
	resp, err := c.CreateBackup(&pb.CreateBackupRequest{
		Username:     username,
		Destination:  dest,
		GcsBucket:    backupCreateBucket,
		Hook:         backupCreateHook,
		Label:        backupCreateLabel,
		HookFormat:   hookFormat,
		AgeRecipient: backupCreateAgeRecipient,
		KeyMode:      keyMode,
		Connection: &pb.PgConnection{
			Database: backupCreateDatabase,
			User:     backupCreateDBUser,
			Password: backupCreateDBPass,
			Host:     backupCreateDBHost,
			Port:     backupCreateDBPort,
		},
	})
	if err != nil {
		return err
	}

	printCreatedBackups(resp)
	return nil
}

// runBackupCreateBox sends a BOX-scope create (#2801). The flags that only
// mean something for a database backup are refused rather than ignored, and
// so is a missing key mode: the daemon would refuse it too, and saying so
// here names the flag.
func runBackupCreateBox(username string, dest pb.BackupDestination, keyMode pb.BackupKeyMode) error {
	for _, f := range []struct {
		flag string
		set  bool
	}{
		{"--database", backupCreateDatabase != ""},
		{"--hook", backupCreateHook != ""},
		{"--hook-format", backupCreateHookFormat != ""},
		{"--label", backupCreateLabel != ""},
		{"--db-user", backupCreateDBUser != ""},
		{"--db-password", backupCreateDBPass != ""},
		{"--db-host", backupCreateDBHost != ""},
		{"--db-port", backupCreateDBPort != 0},
	} {
		if f.set {
			return fmt.Errorf("%s does not apply to a whole-box backup (--box)", f.flag)
		}
	}
	if keyMode == pb.BackupKeyMode_BACKUP_KEY_MODE_UNSPECIFIED {
		return fmt.Errorf("--box needs --key-mode (managed, both or age-recipient): a whole-box backup is never plaintext")
	}

	c, err := newBackupClientFn()
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()

	fmt.Printf("Backing up the whole box of %s to %s (key mode %s)...\n", username, backupCreateDest, keyModeLabel(keyMode))
	resp, err := c.CreateBackup(&pb.CreateBackupRequest{
		Username:     username,
		Scope:        pb.BackupScope_BACKUP_SCOPE_BOX,
		Destination:  dest,
		GcsBucket:    backupCreateBucket,
		AgeRecipient: backupCreateAgeRecipient,
		KeyMode:      keyMode,
	})
	if err != nil {
		return err
	}
	printCreatedBackups(resp)
	return nil
}

// printCreatedBackups renders a CreateBackup response.
func printCreatedBackups(resp *pb.CreateBackupResponse) {
	fmt.Printf("\n✓ %s\n", resp.Message)
	for _, r := range resp.Records {
		if r.Scope == pb.BackupScope_BACKUP_SCOPE_BOX {
			fmt.Printf("  - %s (box: %s)\n", r.Id, r.Database)
		} else {
			fmt.Printf("  - %s (db: %s)\n", r.Id, r.Database)
		}
		fmt.Printf("      Size:     %s\n", humanBytes(r.SizeBytes))
		fmt.Printf("      SHA-256:  %s\n", r.Sha256)
		fmt.Printf("      Location: %s\n", r.Location)
		if r.Encrypted {
			fmt.Printf("      Encrypted: yes (to %s)\n", r.AgeRecipient)
		}
		if r.KeyMode == pb.BackupKeyMode_BACKUP_KEY_MODE_MANAGED || r.KeyMode == pb.BackupKeyMode_BACKUP_KEY_MODE_BOTH {
			fmt.Printf("      Key mode: %s (key version %s)\n", keyModeLabel(r.KeyMode), r.KekId)
		}
	}
	for _, f := range resp.Failures {
		fmt.Printf("  ✗ %s\n", f)
	}
}

// humanBytes renders a byte count in a compact, human-readable form.
func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
