// `containarium security bad-destinations` — list, add, and remove entries
// in the known-bad-destination list the bad-destination rule (#1641)
// matches flow destinations against. CLI-first per the repo convention; the
// MCP tools (internal/mcp/security.go) wrap the same REST calls.
package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

var securityBadDestinationsCmd = &cobra.Command{
	Use:   "bad-destinations",
	Short: "Manage the known-bad-destination list (bad-destination rule, #1641)",
}

var badDestinationsListJSONOut bool

var securityBadDestinationsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List the merged baseline + operator-added known-bad destinations",
	Args:  cobra.NoArgs,
	RunE:  runSecurityBadDestinationsList,
}

var securityBadDestinationsAddCmd = &cobra.Command{
	Use:   "add <cidr> [label]",
	Short: "Add an operator-supplied entry to the known-bad-destination list",
	Long: `Adds an exact IP or CIDR to the known-bad-destination list, effective
immediately — no daemon rebuild or restart required.`,
	Args: cobra.RangeArgs(1, 2),
	RunE: runSecurityBadDestinationsAdd,
}

var securityBadDestinationsRemoveCmd = &cobra.Command{
	Use:   "remove <cidr>",
	Short: "Remove a previously operator-added entry",
	Long:  `Removes a previously operator-added entry. Baseline entries cannot be removed.`,
	Args:  cobra.ExactArgs(1),
	RunE:  runSecurityBadDestinationsRemove,
}

// badDestinationEnvelope mirrors *BadDestinationEntry's grpc-gateway JSON
// shape (protojson default: camelCase field names are already snake_case
// here since every field name is a single word).
type badDestinationEnvelope struct {
	CIDR   string `json:"cidr"`
	Label  string `json:"label"`
	Source string `json:"source"`
}

type listBadDestinationsEnvelope struct {
	Entries []badDestinationEnvelope `json:"entries"`
}

type addBadDestinationEnvelope struct {
	Entry badDestinationEnvelope `json:"entry"`
}

func runSecurityBadDestinationsList(cmd *cobra.Command, _ []string) error {
	if serverAddr == "" {
		return errServerRequired()
	}
	var out listBadDestinationsEnvelope
	url := strings.TrimSuffix(serverAddr, "/") + "/v1/security/bad-destinations"
	if err := getJSON(url, &out); err != nil {
		return err
	}
	if badDestinationsListJSONOut {
		return printJSON(out)
	}
	w := cmd.OutOrStdout()
	if len(out.Entries) == 0 {
		fmt.Fprintln(w, "No known-bad destinations configured.")
		return nil
	}
	fmt.Fprintf(w, "%-24s %-10s %s\n", "CIDR", "SOURCE", "LABEL")
	for _, e := range out.Entries {
		fmt.Fprintf(w, "%-24s %-10s %s\n", e.CIDR, e.Source, e.Label)
	}
	return nil
}

func runSecurityBadDestinationsAdd(cmd *cobra.Command, args []string) error {
	if serverAddr == "" {
		return errServerRequired()
	}
	cidr := args[0]
	label := ""
	if len(args) == 2 {
		label = args[1]
	}
	body, err := json.Marshal(struct {
		Cidr  string `json:"cidr"`
		Label string `json:"label"`
	}{Cidr: cidr, Label: label})
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}
	var out addBadDestinationEnvelope
	url := strings.TrimSuffix(serverAddr, "/") + "/v1/security/bad-destinations"
	if err := postJSON(url, body, &out); err != nil {
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(), "Added %s (%s)\n", out.Entry.CIDR, out.Entry.Label)
	return nil
}

func runSecurityBadDestinationsRemove(cmd *cobra.Command, args []string) error {
	if serverAddr == "" {
		return errServerRequired()
	}
	cidr := args[0]
	url := strings.TrimSuffix(serverAddr, "/") + "/v1/security/bad-destinations/" + cidr
	if err := deleteJSON(url); err != nil {
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(), "Removed %s\n", cidr)
	return nil
}

// postJSON does an admin-authenticated POST with a JSON body and decodes the
// JSON response. Sibling of getJSON (backends_versions.go).
func postJSON(url string, body []byte, out interface{}) error {
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if authToken != "" {
		req.Header.Set("Authorization", "Bearer "+authToken)
	}
	httpClient := &http.Client{Timeout: 10 * time.Second}
	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// deleteJSON does an admin-authenticated DELETE, discarding any response
// body. Sibling of getJSON/postJSON.
func deleteJSON(url string) error {
	req, err := http.NewRequest(http.MethodDelete, url, nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	if authToken != "" {
		req.Header.Set("Authorization", "Bearer "+authToken)
	}
	httpClient := &http.Client{Timeout: 10 * time.Second}
	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	return nil
}

func init() {
	securityBadDestinationsListCmd.Flags().BoolVar(&badDestinationsListJSONOut, "json", false, "Output raw JSON")
	securityBadDestinationsCmd.AddCommand(securityBadDestinationsListCmd)
	securityBadDestinationsCmd.AddCommand(securityBadDestinationsAddCmd)
	securityBadDestinationsCmd.AddCommand(securityBadDestinationsRemoveCmd)
	securityCmd.AddCommand(securityBadDestinationsCmd)
}
