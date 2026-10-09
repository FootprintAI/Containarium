package mcp

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"strings"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
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
	tools := []Tool{
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
				"auto-restorable unless 'hook_format' declares it pg_custom); 'age_recipient' encrypts the dump to a user-held " +
				"age public key before storage, so the platform only holds " +
				"ciphertext. 'key_mode' selects who holds the key on a daemon " +
				"with a backup KMS key configured ('managed': a per-backup key " +
				"wrapped by the KMS; 'both': managed plus the age recipient). " +
				"Mirrors `containarium backup create`.",
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
					"hook_format": map[string]interface{}{
						"type":        "string",
						"description": "Declared format of the hook's output. 'opaque' (default): stored and fetched, never restored or restore-tested by the platform. 'pg_custom': the hook emits a pg_dump -Fc archive, so the backup can be restore-tested (verify_backup) and restored into a named target other than its source. A promise about the hook's output; the daemon does not check it at create time. Only with 'hook'.",
						"enum":        []string{"opaque", "pg_custom"},
					},
					"age_recipient": map[string]interface{}{
						"type":        "string",
						"description": "age public key (age1...) to encrypt the dump to before it is stored, overriding any recipient the tenant has already self-registered as the CONTAINARIUM_BACKUP_AGE_RECIPIENT secret (set_secret). Omit this to use the registered one automatically, or omit both for a plaintext dump. Restore then requires the matching identity file, which the platform never holds.",
					},
					"key_mode": map[string]interface{}{
						"type":        "string",
						"description": "Who holds the key (#2402). 'managed': encrypt to a fresh per-backup identity whose secret the daemon wraps with its KMS key and stores on the record; 'both': managed plus the age recipient, so either opens the file; 'age_recipient': the recipient only, no wrapping. Omit for the daemon default (managed/both when a backup KMS key is configured, otherwise the recipient/plaintext behaviour). A mode the daemon cannot provide is refused, not downgraded. The daemon never unwraps: restore/verify still take the identity, unwrapped under your own KMS credentials.",
						"enum":        []string{"age_recipient", "managed", "both"},
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
						"description": "Backup ID to restore (see list_backups). Omit with latest.",
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
					"target": map[string]interface{}{
						"type":        "string",
						"description": "Container to restore into, <username>-container (default: the backup's own container). A pg_custom hook backup restores only into a target other than its source. Mirrors --target.",
					},
				},
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
						"description": "Backup ID to verify (see list_backups). Omit with latest.",
					},
					"target_username": map[string]interface{}{
						"type":        "string",
						"description": "Tenant whose container is used as the throwaway restore target. Must differ from the backup's own tenant.",
					},
					"db_password": map[string]interface{}{
						"type":        "string",
						"description": "Postgres password on the target. Omit for peer/trust auth.",
					},
					"age_identity_file": map[string]interface{}{
						"type":        "string",
						"description": "Path (on the MCP host) to the age identity file (AGE-SECRET-KEY-1...) for a backup created with age_recipient. Required to verify an encrypted record at all; the platform holds no decryption key. A WRONG identity is reported as a failed check, not a tool error — that is exactly the gap this tool closes: a backup can report success while being encrypted to a key nobody holds, and only an attempted decrypt reveals that. Read from the file so the private key never appears in tool arguments; used for this one call, never stored.",
					},
				},
				"required": []string{"target_username"},
			},
			Handler: handleVerifyBackup,
		},
	}
	// restore_backup and verify_backup share the CLI's key/selection flags (#2403).
	for _, t := range tools {
		if t.Name == "restore_backup" || t.Name == "verify_backup" {
			props := t.InputSchema["properties"].(map[string]interface{})
			for k, v := range managedSelectionProps() {
				props[k] = v
			}
		}
	}
	return tools
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
	keyMode, err := keyModeEnumName(getStringArg(args, "key_mode", ""))
	if err != nil {
		return "", err
	}
	hookFormat, err := hookFormatArg(getStringArg(args, "hook_format", ""))
	if err != nil {
		return "", err
	}
	resp, err := client.CreateBackup(CreateBackupRequest{
		Username:     getStringArg(args, "username", ""),
		Destination:  destEnum,
		GCSBucket:    getStringArg(args, "gcs_bucket", ""),
		Hook:         hook,
		Label:        getStringArg(args, "label", ""),
		HookFormat:   hookFormat,
		AgeRecipient: getStringArg(args, "age_recipient", ""),
		KeyMode:      keyMode,
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
			if r.HookFormat == pb.HookFormat_HOOK_FORMAT_PG_CUSTOM.String() {
				out += fmt.Sprintf("Hook:     %s (pg_custom dump; restore-testable)\n", r.Hook)
			} else {
				out += fmt.Sprintf("Hook:     %s (opaque dump; not auto-restorable)\n", r.Hook)
			}
		}
		if r.Encrypted {
			out += fmt.Sprintf("Encrypted: yes, to %s (restore needs the matching identity file)\n", r.AgeRecipient)
		}
		if r.KeyMode == "BACKUP_KEY_MODE_MANAGED" || r.KeyMode == "BACKUP_KEY_MODE_BOTH" {
			out += fmt.Sprintf("Key mode: %s (key version %s; unwrap the record's wrapped key under your own KMS credentials to restore)\n",
				keyModeArgName(r.KeyMode), r.KekID)
		}
	}
	return out, nil
}

// keyModeEnumName maps the tool's key_mode argument to the proto enum
// NAME the gateway expects (#2402). Empty stays empty — UNSPECIFIED, the
// daemon default — and an unknown value is refused here rather than
// bounced by the gateway as an opaque 400.
func keyModeEnumName(arg string) (string, error) {
	switch arg {
	case "":
		return "", nil
	case "age_recipient":
		return "BACKUP_KEY_MODE_AGE_RECIPIENT", nil
	case "managed":
		return "BACKUP_KEY_MODE_MANAGED", nil
	case "both":
		return "BACKUP_KEY_MODE_BOTH", nil
	default:
		return "", fmt.Errorf("invalid key_mode %q (expected 'age_recipient', 'managed' or 'both')", arg)
	}
}

// keyModeArgName is the inverse: the wire enum name as the tool's own
// vocabulary, for output.
func keyModeArgName(enumName string) string {
	return strings.ToLower(strings.TrimPrefix(enumName, "BACKUP_KEY_MODE_"))
}

// hookFormatArg maps the create_backup hook_format argument to the
// pb.HookFormat value name protojson expects on the wire (#2405), mirroring
// the CLI's --hook-format. Empty stays empty (omitted; daemon default
// opaque).
func hookFormatArg(s string) (string, error) {
	var f pb.HookFormat
	switch s {
	case "":
		return "", nil
	case "opaque":
		f = pb.HookFormat_HOOK_FORMAT_OPAQUE
	case "pg_custom":
		f = pb.HookFormat_HOOK_FORMAT_PG_CUSTOM
	default:
		return "", fmt.Errorf("invalid hook_format %q (expected 'opaque' or 'pg_custom')", s)
	}
	return f.String(), nil
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

// readToolIdentityFile reads the optional age_identity_file argument.
func readToolIdentityFile(args map[string]interface{}) (string, error) {
	path := getStringArg(args, "age_identity_file", "")
	if path == "" {
		return "", nil
	}
	content, err := os.ReadFile(path) // #nosec G304 -- operator-named identity file, read on the MCP host
	if err != nil {
		return "", fmt.Errorf("read age identity file: %w", err)
	}
	id, err := parseAgeIdentityFile(content)
	if err != nil {
		return "", fmt.Errorf("%s: %w", path, err)
	}
	return id, nil
}

func handleRestoreBackup(client API, args map[string]interface{}) (string, error) {
	rec, err := resolveToolBackup(client, args)
	if err != nil {
		return "", err
	}
	ageIdentity, zero, err := toolIdentity(rec, args)
	if err != nil {
		return "", err
	}
	defer zero()
	resp, err := client.RestoreBackup(RestoreBackupRequest{
		ID:              rec.Id,
		Clean:           getBoolArg(args, "clean", false),
		AgeIdentity:     ageIdentity,
		TargetContainer: getStringArg(args, "target", ""),
		Connection: &PgConnectionBody{
			Database: getStringArg(args, "database", ""),
			Password: getStringArg(args, "db_password", ""),
		},
	})
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("✅ %s\n", resp.Message), nil
}

func handleVerifyBackup(client API, args map[string]interface{}) (string, error) {
	rec, err := resolveToolBackup(client, args)
	if err != nil {
		return "", err
	}
	ageIdentity, zero, err := toolIdentity(rec, args)
	if err != nil {
		return "", err
	}
	defer zero()
	resp, err := client.VerifyBackup(VerifyBackupRequest{
		ID:             rec.Id,
		TargetUsername: getStringArg(args, "target_username", ""),
		AgeIdentity:    ageIdentity,
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
