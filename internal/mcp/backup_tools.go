package mcp

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
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
				"size, and SHA-256. Two opt-in options: 'hook' runs the tenant's " +
				"own in-container program and stores its stdout instead of running " +
				"pg_dump (no DB credential needed; the dump is opaque and not " +
				"auto-restorable); 'age_recipient' encrypts the dump to a user-held " +
				"age public key before storage, so the platform only holds " +
				"ciphertext. Mirrors `containarium backup create`.",
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
					"hook": map[string]interface{}{
						"type":        "string",
						"description": "Absolute path of an executable inside the container whose stdout is the dump. Bypasses pg_dump and the db_* fields; no credential crosses to the platform. Bare path, no arguments.",
					},
					"label": map[string]interface{}{
						"type":        "string",
						"description": "Label for a hook backup, used in the backup id (default: the hook's basename).",
					},
					"age_recipient": map[string]interface{}{
						"type":        "string",
						"description": "age public key (age1...) to encrypt the dump to before it is stored, overriding any recipient the tenant has already self-registered as the CONTAINARIUM_BACKUP_AGE_RECIPIENT secret (set_secret). Omit this to use the registered one automatically, or omit both for a plaintext dump. Restore then requires the matching identity file, which the platform never holds.",
					},
				},
				"required": []string{"username"},
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
					"age_identity_file": map[string]interface{}{
						"type":        "string",
						"description": "Path (on the MCP host) to the age identity file (AGE-SECRET-KEY-1...) for a backup created with age_recipient. Read from the file so the private key never appears in tool arguments; used for this one call, never stored.",
					},
				},
				"required": []string{"id"},
			},
			Handler: handleRestoreBackup,
		},
		{
			Name: "verify_backup",
			Description: "Prove a backup is restorable, not merely intact. The recorded " +
				"SHA-256 shows the bytes are unchanged; it cannot show the dump will " +
				"load. Verification restores the dump into a throwaway database inside " +
				"the target container, sanity-checks it, and drops the scratch " +
				"database. NON-DESTRUCTIVE to the source: the container the backup " +
				"came from is never touched, and a target that resolves to it is " +
				"refused. A dump that fails to load is reported as a failed " +
				"verification with the engine's own error, not as a tool error. The " +
				"outcome is recorded on the backup as audit evidence. Mirrors " +
				"`containarium backup verify`.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"id": map[string]interface{}{
						"type":        "string",
						"description": "Backup ID to verify (see list_backups).",
					},
					"target_username": map[string]interface{}{
						"type":        "string",
						"description": "Tenant whose container is used as the throwaway restore target. Must differ from the backup's own tenant.",
					},
					"db_password": map[string]interface{}{
						"type":        "string",
						"description": "Postgres password on the target. Omit for peer/trust auth.",
					},
				},
				"required": []string{"id", "target_username"},
			},
			Handler: handleVerifyBackup,
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

	database := getStringArg(args, "database", "")
	hook := getStringArg(args, "hook", "")
	if database == "" && hook == "" {
		return "", fmt.Errorf("either database or hook is required")
	}
	resp, err := client.CreateBackup(CreateBackupRequest{
		Username:     getStringArg(args, "username", ""),
		Destination:  destEnum,
		GCSBucket:    getStringArg(args, "gcs_bucket", ""),
		Hook:         hook,
		Label:        getStringArg(args, "label", ""),
		AgeRecipient: getStringArg(args, "age_recipient", ""),
		Connection: &PgConnectionBody{
			Database: database,
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
		if r.Hook != "" {
			out += fmt.Sprintf("Hook:     %s (opaque dump; not auto-restorable)\n", r.Hook)
		}
		if r.Encrypted {
			out += fmt.Sprintf("Encrypted: yes, to %s (restore needs the matching identity file)\n", r.AgeRecipient)
		}
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
	var ageIdentity string
	if path := getStringArg(args, "age_identity_file", ""); path != "" {
		content, err := os.ReadFile(path) // #nosec G304 -- operator-named identity file, read on the MCP host
		if err != nil {
			return "", fmt.Errorf("read age identity file: %w", err)
		}
		ageIdentity, err = parseAgeIdentityFile(content)
		if err != nil {
			return "", fmt.Errorf("%s: %w", path, err)
		}
	}
	resp, err := client.RestoreBackup(RestoreBackupRequest{
		ID:          getStringArg(args, "id", ""),
		Clean:       getBoolArg(args, "clean", false),
		AgeIdentity: ageIdentity,
		Connection: &PgConnectionBody{
			Password: getStringArg(args, "db_password", ""),
		},
	})
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("✅ %s\n", resp.Message), nil
}

func handleVerifyBackup(client API, args map[string]interface{}) (string, error) {
	resp, err := client.VerifyBackup(VerifyBackupRequest{
		ID:             getStringArg(args, "id", ""),
		TargetUsername: getStringArg(args, "target_username", ""),
		Connection: &PgConnectionBody{
			Password: getStringArg(args, "db_password", ""),
		},
	})
	if err != nil {
		return "", err
	}

	var b strings.Builder
	v := resp.Verification
	if v == nil {
		return "", fmt.Errorf("daemon returned no verification result")
	}
	passed := v.Result == "VERIFICATION_RESULT_PASSED"
	if passed {
		fmt.Fprintf(&b, "✅ %s\n\n", resp.Message)
	} else {
		fmt.Fprintf(&b, "❌ %s\n\n", resp.Message)
	}
	for _, c := range v.Checks {
		mark := "✓"
		if !c.Passed {
			mark = "✗"
		}
		fmt.Fprintf(&b, "  %s %-18s %s\n", mark, c.Name, c.Detail)
	}
	fmt.Fprintf(&b, "\n  target: %s (scratch db %s, dropped)\n", v.TargetContainer, v.ScratchDatabase)
	fmt.Fprintf(&b, "  when:   %s", v.VerifiedAt)
	if v.VerifiedBy != "" {
		fmt.Fprintf(&b, " by %s", v.VerifiedBy)
	}
	b.WriteString("\n")
	return b.String(), nil
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

// parseAgeIdentityFile extracts the single AGE-SECRET-KEY-1… line from an
// `age-keygen` identity file (comment lines start with #). Same rule as the
// CLI's --age-identity-file: exactly one identity, or it is a guess.
func parseAgeIdentityFile(content []byte) (string, error) {
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
