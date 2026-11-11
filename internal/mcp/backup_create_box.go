package mcp

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/footprintai/containarium/internal/client"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// Whole-box backup (#3504): create_backup with scope "box" is a thin wrapper
// over the function `containarium backup create --box` calls,
// client.CreateBoxBackup (CLI-first, CLAUDE.md).

// createBoxBackupFn is that shared function. A variable only so a test can
// check it is the CLI's.
var createBoxBackupFn = client.CreateBoxBackup

// boxBackupTimeout bounds one whole-box backup call. The daemon exports and
// uploads the box before it answers, which takes far longer than this
// client's 120s default; this is the bound the typed HTTP client puts on
// CreateBackup, so the tool waits as long as `backup create --box --http`.
const boxBackupTimeout = 30 * time.Minute

// newBoxBackupAPI builds the CLI's typed HTTP client from this MCP client's
// transport, base URL and current token, with the longer timeout above. A
// variable so the tool test can fake it.
var newBoxBackupAPI = func(c *Client) (client.BoxBackupAPI, error) {
	if c.tlsConfigErr != nil {
		return nil, fmt.Errorf("MCP client refuses to send request: %w", c.tlsConfigErr)
	}
	token, err := c.readToken()
	if err != nil {
		return nil, fmt.Errorf("authenticate: %w", err)
	}
	return client.NewHTTPClient(c.baseURL, token, client.WithHTTPClient(c.boxBackupHTTPClient()))
}

// boxBackupHTTPClient is this client's transport with boxBackupTimeout, as a
// copy: the tool client's own timeout is unchanged.
func (c *Client) boxBackupHTTPClient() *http.Client {
	hc := *c.httpClient
	hc.Timeout = boxBackupTimeout
	return &hc
}

// CreateBoxBackup runs the shared whole-box backup over this client.
func (c *Client) CreateBoxBackup(p client.BoxBackupParams) (*pb.CreateBackupResponse, error) {
	return createBoxBackupFn(func() (client.BoxBackupAPI, error) { return newBoxBackupAPI(c) }, p)
}

// handleCreateBoxBackup is create_backup with scope "box". The arguments that
// only mean something for a database backup are refused rather than
// ignored, and so is a missing key_mode, before any request is made: the
// same refusals `backup create --box` makes for its flags.
func handleCreateBoxBackup(api API, args map[string]interface{}, dest pb.BackupDestination) (string, error) {
	for _, arg := range []string{"database", "hook", "hook_format", "label", "db_user", "db_password"} {
		if getStringArg(args, arg, "") != "" {
			return "", fmt.Errorf("%s does not apply to a whole-box backup (scope 'box')", arg)
		}
	}
	keyMode, err := keyModeArg(getStringArg(args, "key_mode", ""))
	if err != nil {
		return "", err
	}
	if keyMode == pb.BackupKeyMode_BACKUP_KEY_MODE_UNSPECIFIED {
		return "", fmt.Errorf("scope 'box' needs key_mode ('managed', 'both' or 'age_recipient'): a whole-box backup is never plaintext")
	}
	resp, err := api.CreateBoxBackup(client.BoxBackupParams{
		Box:          getStringArg(args, "username", ""),
		Destination:  dest,
		GCSBucket:    getStringArg(args, "gcs_bucket", ""),
		AgeRecipient: getStringArg(args, "age_recipient", ""),
		KeyMode:      keyMode,
	})
	if err != nil {
		return "", err
	}
	return renderBoxBackup(resp), nil
}

// renderBoxBackup is the tool output for a whole-box backup: the same lines
// create_backup prints for a database backup, with the box named.
func renderBoxBackup(resp *pb.CreateBackupResponse) string {
	var b strings.Builder
	fmt.Fprintf(&b, "✅ %s\n", resp.GetMessage())
	r := resp.GetRecord()
	if r == nil {
		return b.String()
	}
	fmt.Fprintf(&b, "ID:       %s\n", r.GetId())
	fmt.Fprintf(&b, "Box:      %s\n", r.GetDatabase())
	fmt.Fprintf(&b, "Size:     %d bytes\n", r.GetSizeBytes())
	fmt.Fprintf(&b, "SHA-256:  %s\n", r.GetSha256())
	fmt.Fprintf(&b, "Location: %s\n", r.GetLocation())
	if r.GetEncrypted() {
		fmt.Fprintf(&b, "Encrypted: yes, to %s (restore needs the matching identity file)\n", r.GetAgeRecipient())
	}
	if km := r.GetKeyMode(); km == pb.BackupKeyMode_BACKUP_KEY_MODE_MANAGED || km == pb.BackupKeyMode_BACKUP_KEY_MODE_BOTH {
		fmt.Fprintf(&b, "Key mode: %s (key version %s; unwrap the record's wrapped key under your own KMS credentials to restore)\n",
			keyModeArgName(km.String()), r.GetKekId())
	}
	return b.String()
}
