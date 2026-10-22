package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// claimURLFile is where the daemon writes an anonymous box's claim URL or
// token (internal/anonbox.ClaimURLPath). A var so tests can point it at a
// temp file.
var claimURLFile = "/etc/containarium/claim-url"

var claimJSON bool

var claimCmd = &cobra.Command{
	Use:   "claim",
	Short: "Keep this anonymous box: print the sign-up link that binds it to your account",
	Long: `Run INSIDE an anonymous box (one you reached with ssh new.<domain>).

Prints the single-use claim link the daemon minted for this box. Open it,
sign up (or sign in), and the box — same name, same files — becomes yours:
no more expiry, your own keys added, the trial egress limits lifted. The
link expires with the box.

When the daemon was started without --anon-claim-url-base the file holds
the bare token instead of a link; hand that token to an operator
(containarium anon claim <token> --tenant <you>) or the control plane.

  --json   {"url": …, "token": …, "expires_at": …} for scripts`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		raw, err := os.ReadFile(claimURLFile)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("this box is not an anonymous box (no %s) — nothing to claim", claimURLFile)
			}
			return fmt.Errorf("read %s: %w", claimURLFile, err)
		}
		out, err := renderClaim(strings.TrimSpace(string(raw)), claimJSON)
		if err != nil {
			return err
		}
		fmt.Fprint(cmd.OutOrStdout(), out)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(claimCmd)
	claimCmd.Flags().BoolVar(&claimJSON, "json", false, "Print {url, token, expires_at} as JSON")
}

// claimInfo is what the file tells us: a URL carrying the token, or the
// bare token. Expiry is the token's own exp field (the 4th of its six
// dot-separated fields) — read here without the anonbox package so the
// client binary stays free of daemon-side imports.
type claimInfo struct {
	URL       string `json:"url,omitempty"`
	Token     string `json:"token"`
	ExpiresAt string `json:"expires_at,omitempty"`
}

func parseClaimFile(content string) (claimInfo, error) {
	content = strings.TrimSpace(content)
	if content == "" {
		return claimInfo{}, errors.New("claim file is empty")
	}
	info := claimInfo{Token: content}
	if i := strings.Index(content, "?token="); i >= 0 {
		info.URL = content
		info.Token = content[i+len("?token="):]
	}
	parts := strings.Split(info.Token, ".")
	if len(parts) != 6 || parts[0] != "v1" {
		return claimInfo{}, fmt.Errorf("claim token in %s is not in the expected form", claimURLFile)
	}
	if exp, err := strconv.ParseInt(parts[3], 10, 64); err == nil && exp > 0 {
		info.ExpiresAt = time.Unix(exp, 0).UTC().Format(time.RFC3339)
	}
	return info, nil
}

func renderClaim(content string, asJSON bool) (string, error) {
	info, err := parseClaimFile(content)
	if err != nil {
		return "", err
	}
	if asJSON {
		b, err := json.MarshalIndent(info, "", "  ")
		if err != nil {
			return "", err
		}
		return string(b) + "\n", nil
	}
	var sb strings.Builder
	if info.URL != "" {
		sb.WriteString("Keep this box — open this link and sign up:\n\n  " + info.URL + "\n\n")
	} else {
		sb.WriteString("This daemon has no claim URL configured. Your claim token is:\n\n  " + info.Token + "\n\n")
		sb.WriteString("Give it to an operator or the control plane:  containarium anon claim <token> --tenant <you>\n\n")
	}
	if info.ExpiresAt != "" {
		sb.WriteString("The link is single-use and expires with the box at " + info.ExpiresAt + ".\n")
	}
	return sb.String(), nil
}
