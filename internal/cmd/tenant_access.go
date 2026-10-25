package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/spf13/cobra"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

var accessBoth, accessRevoke, accessConfirm bool

type accessEdit struct {
	Destination string   `json:"destination"`
	Add         []string `json:"addSources,omitempty"`
	Remove      []string `json:"removeSources,omitempty"`
	Revision    string   `json:"expectedRevision"`
}
type accessPlan struct {
	Changes []accessEdit `json:"changes"`
}

func init() {
	parent := &cobra.Command{Use: "access", Short: "Preview/apply atomic cross-Tenant ingress changes (admin)"}
	preview := &cobra.Command{Use: "preview <source> <destination>", Args: cobra.ExactArgs(2), RunE: func(cmd *cobra.Command, args []string) error {
		if serverAddr == "" {
			return errServerRequired()
		}
		pairs := [][2]string{{args[0], args[1]}}
		if accessBoth {
			pairs = append(pairs, [2]string{args[1], args[0]})
		}
		plan := accessPlan{}
		for _, pair := range pairs {
			revision, err := readTenantAccessRevision(pair[1])
			if err != nil {
				return err
			}
			if accessRevoke && revision == "absent" {
				continue
			}
			change := accessEdit{Destination: pair[1], Revision: revision}
			if accessRevoke {
				change.Remove = []string{pair[0]}
			} else {
				change.Add = []string{pair[0]}
			}
			plan.Changes = append(plan.Changes, change)
		}
		if len(plan.Changes) == 0 {
			return fmt.Errorf("no existing destination policy to revoke; no write required")
		}
		encoded, err := json.MarshalIndent(plan, "", "  ")
		if err != nil {
			return err
		}
		fmt.Fprintln(cmd.OutOrStdout(), string(encoded))
		return nil
	}}
	preview.Flags().BoolVar(&accessBoth, "both", false, "Edit both destination ingress policies in one transaction")
	preview.Flags().BoolVar(&accessRevoke, "revoke", false, "Remove only the specified ingress authorization")
	apply := &cobra.Command{Use: "apply <reviewed-plan.json> --confirm", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		if serverAddr == "" {
			return errServerRequired()
		}
		if !accessConfirm {
			return fmt.Errorf("review the exact plan and pass --confirm")
		}
		f, err := os.Open(args[0])
		if err != nil {
			return err
		}
		defer func() { _ = f.Close() }()
		dec := json.NewDecoder(io.LimitReader(f, 65537))
		dec.DisallowUnknownFields()
		var plan accessPlan
		if err := dec.Decode(&plan); err != nil {
			return err
		}
		var extra interface{}
		if err := dec.Decode(&extra); err != io.EOF {
			return fmt.Errorf("one bounded JSON plan required")
		}
		var out interface{}
		if err := doJSON("POST", strings.TrimSuffix(serverAddr, "/")+"/v1/network-policies/tenant-access", plan, &out); err != nil {
			return err
		}
		return printJSON(out)
	}}
	apply.Flags().BoolVar(&accessConfirm, "confirm", false, "Confirm only the reviewed ingress changes; conflicts abort the entire batch")

	parent.AddCommand(preview, apply)
	networkPolicyCmd.AddCommand(parent)
}
func readTenantAccessRevision(tenant string) (string, error) {
	req, err := http.NewRequest("GET", strings.TrimSuffix(serverAddr, "/")+"/v1/network-policies/"+url.PathEscape(tenant), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+authToken)
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return "absent", nil
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("policy read status %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024+1))
	if err != nil || len(raw) > 4*1024*1024 {
		return "", fmt.Errorf("invalid policy response")
	}
	var out struct {
		Revision string `json:"revision"`
	}
	if err := json.NewDecoder(bytes.NewReader(raw)).Decode(&out); err != nil {
		return "", err
	}
	if len(out.Revision) != 64 {
		return "", fmt.Errorf("provider lacks safe revision-checked Tenant access contract")
	}
	return out.Revision, nil
}
