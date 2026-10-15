//go:build !windows && !containarium_client

package cmd

import (
	"github.com/footprintai/containarium/internal/sentinel/sshcontrol"
	"github.com/spf13/cobra"
	"os"
	"os/signal"
	"syscall"
)

// init exposes the same controller for standalone operator-managed SSH gateways.
func init() { sentinelCmd.AddCommand(newSSHUpstreamControlCommand()) }

// newSSHUpstreamControlCommand requires an explicit typed inventory and policy.
func newSSHUpstreamControlCommand() *cobra.Command {
	var policyPath, state, socket string
	c := &cobra.Command{Use: "ssh-upstream-control", Short: "Serve private shared SSH backend admission", Args: cobra.NoArgs}
	c.Flags().StringVar(&policyPath, "policy", "", "Strict protobuf JSON policy with authoritative static routes")
	c.Flags().StringVar(&state, "state", sshcontrol.DefaultState, "Private durable risk checkpoint")
	c.Flags().StringVar(&socket, "socket", sshcontrol.DefaultSocket, "Private Unix control socket")
	_ = c.MarkFlagRequired("policy")
	c.RunE = func(cmd *cobra.Command, _ []string) error {
		data, err := os.ReadFile(policyPath)
		if err != nil {
			return err
		}
		policy, err := sshcontrol.ParsePolicy(data)
		if err != nil {
			return err
		}
		controller, err := sshcontrol.New(sshcontrol.Config{Policy: policy, StatePath: state})
		if err != nil {
			return err
		}
		defer func() { _ = controller.Close() }()
		stop, err := sshcontrol.ListenControl(socket, controller)
		if err != nil {
			return err
		}
		defer stop()
		ctx, cancel := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
		defer cancel()
		<-ctx.Done()
		return nil
	}
	return c
}
