//go:build !containarium_client

package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/footprintai/containarium/internal/hostharden"
)

// applyMetadataBlock is the #1103 fix-3 mitigation shared by `cloud enroll`
// and `pool join`: block the container bridge's FORWARDED traffic to the
// cloud metadata endpoint, then install a systemd unit so the rule survives
// a reboot. Every failure here is a printed warning, never a returned
// error — this narrows a real risk but was never the thing either command
// exists to do, so it must not turn a successful join/enroll into a
// reported failure.
//
// No !windows tag: this file has the same build constraint as cloud.go (the
// only caller that also builds on Windows), and on Windows the resulting
// exec.Command calls simply fail fast (no iptables/incus binaries) and get
// reported the same non-fatal way.
func applyMetadataBlock(cmd *cobra.Command, bridge string, skip bool) {
	if skip {
		return
	}
	bin, err := os.Executable()
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "⚠ could not resolve this binary's path (%v); skipping the metadata-endpoint block (#1103)\n", err)
		return
	}
	applied, detail, err := hostharden.BlockMetadataFromBridge(bridge)
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(),
			"⚠ could not block the cloud metadata endpoint from the container bridge (%v)\n"+
				"  a tenant workload that escapes its container may be able to reach instance credentials via %s\n"+
				"  pass --no-block-metadata to silence this, or fix and re-run `containarium hostharden block-metadata %s`\n",
			err, hostharden.MetadataIP, bridge)
		return
	}
	mark := "="
	if applied {
		mark = "✓"
	}
	fmt.Fprintf(cmd.OutOrStdout(), "%s metadata-endpoint block (#1103): %s\n", mark, detail)
	if err := hostharden.InstallPersistentUnit(bin, bridge); err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "⚠ metadata block applied but the reboot-persistence unit failed to install (%v)\n  the rule will NOT survive a reboot until this is fixed\n", err)
	}
}
