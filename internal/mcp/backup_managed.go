package mcp

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/footprintai/containarium/internal/backupkey"
	"github.com/footprintai/containarium/pkg/core/secrets"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// managedKMSLoader builds the MCP host operator's own KMS client for
// managed=true (#2403), the same loader the CLI's --managed uses. Tests
// replace it with a fake.
var managedKMSLoader backupkey.KMSLoader = backupkey.LoadOperatorKMS

// managedSelectionProps are the restore_backup / verify_backup inputs that
// mirror the CLI's --managed, --latest, --user and --database.
func managedSelectionProps() map[string]interface{} {
	return map[string]interface{}{
		"managed": map[string]interface{}{
			"type":        "boolean",
			"description": "Unwrap the record's managed key (key_mode managed/both) on the MCP host with the operator's own cloud credentials (CONTAINARIUM_KMS_BACKEND=gcp, CONTAINARIUM_GCP_KMS_TOKEN=$(gcloud auth print-access-token)); the decrypt is audited by the KMS. A KMS permission error stops the call before any restore/verify reaches the host. Exclusive with age_identity_file. Mirrors --managed.",
		},
		"latest": map[string]interface{}{
			"type":        "boolean",
			"description": "Act on the newest backup for 'username' and 'database' instead of a named id. Mirrors --latest.",
		},
		"username": map[string]interface{}{
			"type":        "string",
			"description": "Tenant whose backups are searched: required with latest; with managed and an id, narrows the record lookup.",
		},
		"database": map[string]interface{}{
			"type":        "string",
			"description": "Database whose newest backup latest selects. On restore_backup it is also the database restored into (default: the backup's own), as with the CLI's --database.",
		},
	}
}

// resolveToolBackup returns the record a restore/verify tool acts on,
// with the same rules as the CLI (backupSelection): an id, or latest with
// username and database, never both; and a managed key never mixed with
// an identity file.
func resolveToolBackup(client API, args map[string]interface{}) (*pb.BackupRecord, error) {
	id := getStringArg(args, "id", "")
	latest, managed := getBoolArg(args, "latest", false), getBoolArg(args, "managed", false)
	user, database := getStringArg(args, "username", ""), getStringArg(args, "database", "")
	if managed && getStringArg(args, "age_identity_file", "") != "" {
		return nil, fmt.Errorf("managed and age_identity_file are mutually exclusive: pick the key source")
	}
	switch {
	case latest && id != "":
		return nil, fmt.Errorf("latest and id are mutually exclusive")
	case latest && (user == "" || database == ""):
		return nil, fmt.Errorf("latest needs username and database")
	case !latest && id == "":
		return nil, fmt.Errorf("id is required (or latest with username and database)")
	case !latest && !managed:
		return &pb.BackupRecord{Id: id}, nil
	}
	resp, err := client.ListBackups(user)
	if err != nil {
		return nil, err
	}
	recs := make([]*pb.BackupRecord, 0, len(resp.Records))
	for _, r := range resp.Records {
		wrapped, err := base64.StdEncoding.DecodeString(r.WrappedKey)
		if err != nil {
			return nil, fmt.Errorf("backup %s: wrapped key is not base64: %w", r.ID, err)
		}
		pr := &pb.BackupRecord{Id: r.ID, Username: r.Username, Database: r.Database, CreatedAt: r.CreatedAt, WrappedKey: wrapped, KekId: r.KekID}
		if !latest && r.ID == id {
			return pr, nil
		}
		recs = append(recs, pr)
	}
	if !latest {
		return nil, fmt.Errorf("backup %s not found", id)
	}
	return backupkey.Newest(recs, user, database)
}

// toolIdentity returns the age identity for a restore/verify tool call
// (from the managed key or the identity file, or none) and a function
// that zeroes the unwrapped buffer once the request has been sent.
func toolIdentity(rec *pb.BackupRecord, args map[string]interface{}) (string, func(), error) {
	if getBoolArg(args, "managed", false) {
		secret, err := backupkey.UnwrapIdentity(context.Background(), managedKMSLoader, rec)
		if err != nil {
			return "", func() {}, err
		}
		return string(secret), func() { secrets.ZeroBytes(secret) }, nil
	}
	id, err := readToolIdentityFile(args)
	return id, func() {}, err
}
