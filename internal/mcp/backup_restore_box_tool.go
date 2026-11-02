package mcp

import (
	"fmt"

	"github.com/footprintai/containarium/internal/client"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// Whole-box restore (#3358): restore_box_backup is a thin wrapper over the
// function `containarium backup restore --box` calls,
// client.RestoreBoxBackupFromFile (CLI-first, CLAUDE.md).

// restoreBoxFn is that shared function. A variable only so a test can check
// it is the CLI's.
var restoreBoxFn = client.RestoreBoxBackupFromFile

// newBoxRestoreAPI builds the CLI's typed HTTP client from this MCP
// client's transport, base URL and current token. A variable so the tool
// test can fake it.
var newBoxRestoreAPI = func(c *Client) (client.BoxRestoreAPI, error) {
	if c.tlsConfigErr != nil {
		return nil, fmt.Errorf("MCP client refuses to send request: %w", c.tlsConfigErr)
	}
	token, err := c.readToken()
	if err != nil {
		return nil, fmt.Errorf("authenticate: %w", err)
	}
	return client.NewHTTPClient(c.baseURL, token, client.WithHTTPClient(c.httpClient))
}

// RestoreBoxBackup runs the shared box restore over this client.
func (c *Client) RestoreBoxBackup(p client.BoxRestoreParams) (*pb.RestoreBoxBackupResponse, error) {
	return restoreBoxFn(func() (client.BoxRestoreAPI, error) { return newBoxRestoreAPI(c) }, p)
}

func restoreBoxBackupTool() Tool {
	return Tool{
		Name: "restore_box_backup",
		Description: "Restore a whole-box backup (one taken with create_backup's box scope, " +
			"or `containarium backup create <box> --box`) into a new box, left stopped. " +
			"The backup must be a whole-box backup of 'box'. A box named 'as' that already " +
			"exists is refused unless force is true, and force replaces only a stopped box: " +
			"a running box is always refused. A non-admin token can restore only into a box " +
			"named for its own tenant, so the default '<box>-restored' needs an admin token. " +
			"Same function as `containarium backup restore --box`.",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"box": map[string]interface{}{
					"type":        "string",
					"description": "The box the backup was taken of. Mirrors --box.",
				},
				"backup": map[string]interface{}{
					"type":        "string",
					"description": "ID of the whole-box backup (see list_backups). Mirrors --backup.",
				},
				"as": map[string]interface{}{
					"type":        "string",
					"description": "Name of the box to restore into (default: <box>-restored). Mirrors --as.",
				},
				"force": map[string]interface{}{
					"type":        "boolean",
					"description": "Replace an existing STOPPED box of that name. A running box is always refused. Default false. Mirrors --force.",
				},
				"age_identity_file": map[string]interface{}{
					"type":        "string",
					"description": "Path (on the MCP host) to the age identity file (AGE-SECRET-KEY-1...) that opens the backup. Required: a whole-box backup is always encrypted. Read from the file so the private key never appears in tool arguments; used for this one call, never stored.",
				},
			},
			"required": []string{"box", "backup", "age_identity_file"},
		},
		Handler: handleRestoreBoxBackup,
	}
}

func handleRestoreBoxBackup(api API, args map[string]interface{}) (string, error) {
	resp, err := api.RestoreBoxBackup(client.BoxRestoreParams{
		Box:             getStringArg(args, "box", ""),
		BackupID:        getStringArg(args, "backup", ""),
		As:              getStringArg(args, "as", ""),
		Force:           getBoolArg(args, "force", false),
		AgeIdentityFile: getStringArg(args, "age_identity_file", ""),
	})
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("✅ %s\nBox: %s (stopped)\n", resp.Message, resp.Box), nil
}
