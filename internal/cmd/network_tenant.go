package cmd

import (
	"fmt"
	"github.com/footprintai/containarium/internal/client"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/encoding/protojson"
)

func init() {
	parent := &cobra.Command{Use: "network-tenant", Short: "Query native network Tenant creation capability"}
	parent.AddCommand(&cobra.Command{Use: "capabilities", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		if serverAddr == "" {
			return errServerRequired()
		}
		return runNetworkTenantCapabilities(cmd)
	}})
	rootCmd.AddCommand(parent)
}
func runNetworkTenantCapabilities(cmd *cobra.Command) error {
	if httpMode {
		c, err := client.NewHTTPClient(serverAddr, authToken)
		if err != nil {
			return err
		}
		defer func() { _ = c.Close() }()
		out, err := c.GetNetworkTenantCapabilities()
		if err != nil {
			return err
		}
		raw, err := protojson.MarshalOptions{Indent: "  ", EmitUnpopulated: true}.Marshal(out)
		if err != nil {
			return err
		}
		fmt.Fprintln(cmd.OutOrStdout(), string(raw))
		return nil
	}
	c, err := client.NewGRPCClient(serverAddr, certsDir, insecure)
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	out, err := c.GetNetworkTenantCapabilities()
	if err != nil {
		return err
	}
	raw, err := protojson.MarshalOptions{Indent: "  ", EmitUnpopulated: true}.Marshal(out)
	if err != nil {
		return err
	}
	fmt.Fprintln(cmd.OutOrStdout(), string(raw))
	return nil
}
