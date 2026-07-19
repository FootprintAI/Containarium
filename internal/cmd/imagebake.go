package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/footprintai/containarium/pkg/core/container"
	"github.com/footprintai/containarium/pkg/core/ostype"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

var (
	bakeImage  string
	bakePodman bool
	bakeOSType string
)

var imageBakeCmd = &cobra.Command{
	Use:   "image-bake",
	Short: "Bake a provisioned base image so creates skip the in-container package install",
	Long: `Bake a base image (#1037): launch a throwaway container from the source
image, run the exact provisioning a create would (package repos, podman,
services — no user, no stack), and publish the result as a local image under
a deterministic alias.

Afterwards, every stackless 'containarium create' for the same image/podman
combination clones the baked image and skips the multi-minute in-container
install — creates drop from minutes to roughly clone+boot+user setup.

Re-run this on a schedule (cron/systemd timer) to pick up security updates:
a re-bake re-points the alias at the fresh image and reaps the replaced one.
Delete the alias ('incus image alias delete <alias>') to fall back to full
per-create provisioning.

Runs against the local Incus daemon on the backend host (like the daemon's
own create path). Not available in remote --server mode.`,
	Args: cobra.NoArgs,
	RunE: runImageBake,
}

func init() {
	rootCmd.AddCommand(imageBakeCmd)
	imageBakeCmd.Flags().StringVar(&bakeImage, "image", "images:ubuntu/24.04", "Source image to bake from (same format as create --image)")
	imageBakeCmd.Flags().BoolVar(&bakePodman, "podman", true, "Bake with Podman support (must match the creates that will use it)")
	imageBakeCmd.Flags().StringVar(&bakeOSType, "os-type", "", "Container OS type: ubuntu, rocky9, rhel9 (overrides --image, same rule as create)")
}

func runImageBake(cmd *cobra.Command, args []string) error {
	if serverAddr != "" {
		return fmt.Errorf("image-bake runs on the backend host against local Incus; it is not available in --server mode (SSH to the host and run it there)")
	}

	osType := pb.OSType_OS_TYPE_UNSPECIFIED
	if bakeOSType != "" {
		osType = ostype.OSTypeFromString(bakeOSType)
		if osType == pb.OSType_OS_TYPE_UNSPECIFIED {
			return fmt.Errorf("invalid --os-type %q (expected ubuntu, rocky9, or rhel9)", bakeOSType)
		}
	}

	mgr, err := container.New()
	if err != nil {
		return fmt.Errorf("failed to connect to Incus: %w", err)
	}

	res, err := mgr.BakeBaseImage(container.BakeOptions{
		Image:        bakeImage,
		OSType:       osType,
		EnablePodman: bakePodman,
		Verbose:      true,
	})
	if err != nil {
		return err
	}

	fmt.Println()
	fmt.Printf("✓ Baked %s\n", res.Alias)
	fmt.Printf("  Source:      %s\n", res.SourceImage)
	fmt.Printf("  Fingerprint: %s\n", res.Fingerprint)
	fmt.Println()
	fmt.Println("Stackless creates for this image/podman combination now clone the")
	fmt.Println("baked image and skip the in-container package install. Re-run this")
	fmt.Println("command periodically to pick up security updates.")
	return nil
}
