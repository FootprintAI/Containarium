package mcp

import (
	"fmt"
	"strings"
)

// backupTools is the MCP-side catalog for the database-backup feature.
// Defined as a function (not a file-scope slice literal) so the
// registration list in tools.go can pull it in via backupTools() — keeps
// tools.go's slice literal manageable.
//
// Per CLAUDE.md: every tool here is a thin wrapper over the same REST
// endpoint the CLI's `containarium backup` subcommands call (the generated
// BackupService gateway). No agent-only code path.
func backupTools() []Tool {
	return []Tool{
		{
			Name: "create_backup",
			Description: "Back up a tenant's database off-host. Runs pg_dump inside " +
				"the tenant's container and stores the compressed dump in a host " +
				"backup directory (dest 'local') or a GCS bucket (dest 'gcs'). The " +
				"point is off-host durability — a dump never shares a failure " +
				"domain with the database it protects. Returns the backup ID, " +
				"size, and SHA-256. Mirrors `containarium backup create`.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"username": map[string]interface{}{
						"type":        "string",
						"description": "Tenant whose container holds the database.",
					},
					"database": map[string]interface{}{
						"type":        "string",
						"description": "Logical database name to dump.",
					},
					"dest": map[string]interface{}{
						"type":        "string",
						"description": "Destination: 'local' (host backup dir) or 'gcs'. Default 'local'.",
						"enum":        []string{"local", "gcs"},
					},
					"gcs_bucket": map[string]interface{}{
						"type":        "string",
						"description": "GCS bucket/prefix for dest 'gcs', e.g. 'gs://my-backups/pg'. Required when dest=gcs.",
					},
					"db_user": map[string]interface{}{
						"type":        "string",
						"description": "Postgres role. Default 'postgres'.",
					},
					"db_password": map[string]interface{}{
						"type":        "string",
						"description": "Postgres password. Omit for peer/trust auth. Passed via PGPASSWORD inside the container, never on argv.",
					},
				},
				"required": []string{"username", "database"},
			},
			Handler: handleCreateBackup,
		},
		{
			Name: "list_backups",
			Description: "List stored database backups (newest first), optionally " +
				"filtered by tenant. Returns ID, database, timestamp, size, " +
				"destination, and location for each. Mirrors `containarium backup list`.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"username": map[string]interface{}{
						"type":        "string",
						"description": "Optional tenant filter. Omit for all tenants (admin).",
					},
				},
			},
			Handler: handleListBackups,
		},
		{
			Name: "restore_backup",
			Description: "Restore a stored dump back into its container's database " +
				"via pg_restore. The dump is SHA-256 verified before it touches " +
				"the database. DESTRUCTIVE when clean=true (drops objects before " +
				"recreating). Discover backup IDs with list_backups. Mirrors " +
				"`containarium backup restore`.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"id": map[string]interface{}{
						"type":        "string",
						"description": "Backup ID to restore (see list_backups).",
					},
					"clean": map[string]interface{}{
						"type":        "boolean",
						"description": "Pass --clean --if-exists to pg_restore (drop objects first). Default false.",
					},
					"db_password": map[string]interface{}{
						"type":        "string",
						"description": "Postgres password. Omit for peer/trust auth.",
					},
				},
				"required": []string{"id"},
			},
			Handler: handleRestoreBackup,
		},
	}
}

func handleCreateBackup(client API, args map[string]interface{}) (string, error) {
	dest := getStringArg(args, "dest", "local")
	var destEnum string
	switch dest {
	case "local":
		destEnum = "BACKUP_DESTINATION_LOCAL"
	case "gcs":
		destEnum = "BACKUP_DESTINATION_GCS"
	default:
		return "", fmt.Errorf("invalid dest %q (expected 'local' or 'gcs')", dest)
	}

	resp, err := client.CreateBackup(CreateBackupRequest{
		Username:    getStringArg(args, "username", ""),
		Destination: destEnum,
		GCSBucket:   getStringArg(args, "gcs_bucket", ""),
		Connection: &PgConnectionBody{
			Database: getStringArg(args, "database", ""),
			User:     getStringArg(args, "db_user", ""),
			Password: getStringArg(args, "db_password", ""),
		},
	})
	if err != nil {
		return "", err
	}
	out := fmt.Sprintf("✅ %s\n", resp.Message)
	if r := resp.Record; r != nil {
		out += fmt.Sprintf("ID:       %s\n", r.ID)
		out += fmt.Sprintf("Size:     %s bytes\n", r.SizeBytes)
		out += fmt.Sprintf("SHA-256:  %s\n", r.SHA256)
		out += fmt.Sprintf("Location: %s\n", r.Location)
	}
	return out, nil
}

func handleListBackups(client API, args map[string]interface{}) (string, error) {
	resp, err := client.ListBackups(getStringArg(args, "username", ""))
	if err != nil {
		return "", err
	}
	if len(resp.Records) == 0 {
		return "No backups found.", nil
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%-34s %-10s %-12s %-22s %-6s %s\n", "ID", "USER", "DATABASE", "CREATED", "DEST", "LOCATION")
	for _, r := range resp.Records {
		fmt.Fprintf(&b, "%-34s %-10s %-12s %-22s %-6s %s\n",
			r.ID, r.Username, r.Database, r.CreatedAt, backupDestLabel(r.Destination), r.Location)
	}
	return b.String(), nil
}

func handleRestoreBackup(client API, args map[string]interface{}) (string, error) {
	resp, err := client.RestoreBackup(RestoreBackupRequest{
		ID:    getStringArg(args, "id", ""),
		Clean: getBoolArg(args, "clean", false),
		Connection: &PgConnectionBody{
			Password: getStringArg(args, "db_password", ""),
		},
	})
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("✅ %s\n", resp.Message), nil
}

// backupDestLabel renders the proto enum name as a short label.
func backupDestLabel(enumName string) string {
	switch enumName {
	case "BACKUP_DESTINATION_LOCAL":
		return "local"
	case "BACKUP_DESTINATION_GCS":
		return "gcs"
	default:
		return enumName
	}
}
