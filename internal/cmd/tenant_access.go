package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/footprintai/containarium/internal/client"
	"github.com/footprintai/containarium/pkg/core/incus"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/spf13/cobra"
	"io"
)

var accessBoth, accessRevoke, accessConfirm bool

// accessEdit is one reviewed destination change in a plan file. The plan stays
// a plain reviewable JSON document; apply converts it to the typed proto.
type accessEdit struct {
	Destination string   `json:"destination"`
	Add         []string `json:"addSources,omitempty"`
	Remove      []string `json:"removeSources,omitempty"`
	Revision    string   `json:"expectedRevision"`
}
type accessPlan struct {
	Changes []accessEdit `json:"changes"`
}

// tenantAccessClient is the typed surface the access commands use. Both
// transports satisfy it.
type tenantAccessClient interface {
	GetNetworkPolicy(tenant string) (*pb.GetNetworkPolicyResponse, error)
	PatchTenantAccess(req *pb.PatchTenantAccessRequest) (*pb.PatchTenantAccessResponse, error)
}

func newTenantAccessClient() (tenantAccessClient, error) {
	if serverAddr == "" {
		return nil, errServerRequired()
	}
	if httpMode {
		return client.NewHTTPClient(serverAddr, authToken)
	}
	return client.NewGRPCClient(serverAddr, certsDir, insecure)
}

func init() {
	parent := &cobra.Command{Use: "access", Short: "Preview/apply atomic cross-Tenant ingress changes (admin)"}
	preview := &cobra.Command{Use: "preview <source> <destination>", Args: cobra.ExactArgs(2), RunE: func(cmd *cobra.Command, args []string) error {
		c, err := newTenantAccessClient()
		if err != nil {
			return err
		}
		pairs := [][2]string{{args[0], args[1]}}
		if accessBoth {
			pairs = append(pairs, [2]string{args[1], args[0]})
		}
		plan := accessPlan{}
		for _, pair := range pairs {
			revision, err := readTenantAccessRevision(c, pair[1])
			if err != nil {
				return err
			}
			if accessRevoke && revision == incus.TenantAccessAbsentRevision {
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
		if !accessConfirm {
			return fmt.Errorf("review the exact plan and pass --confirm")
		}
		c, err := newTenantAccessClient()
		if err != nil {
			return err
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
		req := &pb.PatchTenantAccessRequest{}
		for _, e := range plan.Changes {
			req.Changes = append(req.Changes, &pb.TenantAccessChange{
				Destination:      e.Destination,
				AddSources:       e.Add,
				RemoveSources:    e.Remove,
				ExpectedRevision: e.Revision,
			})
		}
		out, err := c.PatchTenantAccess(req)
		if err != nil {
			return err
		}
		return printJSON(out)
	}}
	apply.Flags().BoolVar(&accessConfirm, "confirm", false, "Confirm only the reviewed ingress changes; conflicts abort the entire batch")

	parent.AddCommand(preview, apply)
	networkPolicyCmd.AddCommand(parent)
}

// readTenantAccessRevision reads one destination's whole-policy revision
// through the typed policy read; a missing policy is the documented absent
// sentinel, not an error.
func readTenantAccessRevision(c tenantAccessClient, tenant string) (string, error) {
	out, err := c.GetNetworkPolicy(tenant)
	if err != nil {
		if errors.Is(err, client.ErrNetworkPolicyAbsent) {
			return incus.TenantAccessAbsentRevision, nil
		}
		return "", err
	}
	rev := out.GetRevision()
	if len(rev) != 64 {
		return "", fmt.Errorf("provider lacks safe revision-checked Tenant access contract")
	}
	return rev, nil
}
