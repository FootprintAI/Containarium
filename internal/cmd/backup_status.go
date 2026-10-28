package cmd

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/footprintai/containarium/internal/client"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/spf13/cobra"
)

// backupAgeRecipientSecret is the per-tenant secret a scheduled backup
// encrypts to (#1836). Mirrors the daemon's constant; the name, not a value.
const backupAgeRecipientSecret = "CONTAINARIUM_BACKUP_AGE_RECIPIENT" // #nosec G101 -- secret NAME, not a credential value

// defaultBackupTenantsConf is where backup-all-tenants.sh reads its tenants.
const defaultBackupTenantsConf = "/etc/containarium/backup-tenants.conf"

var backupStatusConf string

var backupStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Check that every tenant in the nightly backup config will be encrypted",
	Long: `List the tenants named in backup-tenants.conf (the nightly
backup-all-tenants.sh config) and check, on this daemon, that each has a
CONTAINARIUM_BACKUP_AGE_RECIPIENT secret registered (#3169).

A tenant with no recipient gets its nightly dump stored UNENCRYPTED unless
the daemon has a managed backup key configured; the daemon reports that, and
when it does, tenants with no recipient are listed as OK. Registered secrets are
stored per daemon and do not travel with a copied container, so run this
after moving a tenant to another host, before its first backup there.
Exits non-zero when any tenant has no recipient or could not be checked.

Examples:
  containarium backup status --server <host>
  containarium backup status --conf ./backup-tenants.conf --server <host>`,
	Args: cobra.NoArgs,
	RunE: runBackupStatus,
}

func init() {
	confDefault := os.Getenv("CONTAINARIUM_BACKUP_CONF")
	if confDefault == "" {
		confDefault = defaultBackupTenantsConf
	}
	backupStatusCmd.Flags().StringVar(&backupStatusConf, "conf", confDefault,
		"tenant config read by backup-all-tenants.sh (env CONTAINARIUM_BACKUP_CONF)")
	backupCmd.AddCommand(backupStatusCmd)
}

// backupSecretsLister is the part of the typed client the status check
// needs. Both the gRPC and HTTP clients satisfy it.
type backupSecretsLister interface {
	ListSecrets(username string) ([]*pb.SecretMetadata, error)
}

type backupSecretsClient interface {
	backupSecretsLister
	// ManagedBackupKeyConfigured reports whether the daemon has a managed
	// backup key (SystemInfo.managed_backup_key_configured, #3213).
	ManagedBackupKeyConfigured() (bool, error)
	Close() error
}

// newBackupSecretsClientFn is the seam tests substitute.
var newBackupSecretsClientFn = func() (backupSecretsClient, error) {
	if serverAddr == "" {
		return nil, fmt.Errorf("--server is required")
	}
	if httpMode {
		return client.NewHTTPClient(serverAddr, authToken)
	}
	return client.NewGRPCClient(serverAddr, certsDir, insecure)
}

func runBackupStatus(cmd *cobra.Command, args []string) error {
	tenants, err := readBackupConfTenants(backupStatusConf)
	if err != nil {
		return err
	}
	if len(tenants) == 0 {
		fmt.Printf("No tenants configured in %s.\n", backupStatusConf)
		return nil
	}
	c, err := newBackupSecretsClientFn()
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()

	// Fail safe: if the daemon cannot say (older daemon, or the caller may
	// not read system info), assume there is no managed key, so an
	// unregistered tenant is still flagged rather than silently passed.
	managedKey, err := c.ManagedBackupKeyConfigured()
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not tell whether the daemon has a managed backup key (%v); treating tenants with no recipient as unencrypted\n", err)
		managedKey = false
	}

	fmt.Printf("Backup encryption for tenants in %s:\n", backupStatusConf)
	if missing := checkBackupRecipients(os.Stdout, c, tenants, managedKey); missing > 0 {
		return fmt.Errorf("%d of %d configured tenant(s) have no backup recipient on this daemon or could not be checked", missing, len(tenants))
	}
	return nil
}

// readBackupConfTenants returns the distinct tenants named in a
// backup-tenants.conf, in file order. The tenant is the first
// whitespace-separated field; blank lines and '#' comments are skipped,
// as backup-all-tenants.sh does.
func readBackupConfTenants(path string) ([]string, error) {
	f, err := os.Open(path) // #nosec G304 -- operator-named config path
	if err != nil {
		return nil, fmt.Errorf("read backup config: %w", err)
	}
	defer func() { _ = f.Close() }()

	var tenants []string
	seen := map[string]bool{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) == 0 || strings.HasPrefix(fields[0], "#") {
			continue
		}
		if !seen[fields[0]] {
			seen[fields[0]] = true
			tenants = append(tenants, fields[0])
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read backup config: %w", err)
	}
	return tenants, nil
}

// checkBackupRecipients prints one line per tenant and returns how many
// have no registered recipient or could not be checked. A tenant whose
// secrets cannot be listed counts as missing: the check must not pass on
// an answer it never got. managedKey is the daemon's report that it has a
// managed backup key (#3213): it encrypts every dump, so a tenant with no
// registered recipient is then fine.
func checkBackupRecipients(w io.Writer, l backupSecretsLister, tenants []string, managedKey bool) int {
	missing := 0
	for _, tenant := range tenants {
		secrets, err := l.ListSecrets(tenant)
		if err != nil {
			missing++
			_, _ = fmt.Fprintf(w, "  ? %s — could not check: %v\n", tenant, err)
			continue
		}
		registered := false
		for _, s := range secrets {
			if s.Name == backupAgeRecipientSecret {
				registered = true
				break
			}
		}
		if registered {
			_, _ = fmt.Fprintf(w, "  ✓ %s — age recipient registered\n", tenant)
			continue
		}
		if managedKey {
			_, _ = fmt.Fprintf(w, "  ✓ %s — no age recipient registered; dump encrypted by the daemon's managed backup key\n", tenant)
			continue
		}
		missing++
		_, _ = fmt.Fprintf(w, "  ✗ %s — no %s registered: its dump will be stored UNENCRYPTED (this daemon reports no managed backup key)\n",
			tenant, backupAgeRecipientSecret)
	}
	return missing
}
