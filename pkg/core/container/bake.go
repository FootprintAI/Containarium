package container

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/footprintai/containarium/pkg/core/incus"
	"github.com/footprintai/containarium/pkg/core/ostype"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/footprintai/containarium/pkg/version"
)

// Baked base images (#1037).
//
// Every create used to repeat identical, network-bound provisioning inside
// the fresh instance (apt update, podman repo + install, service enablement)
// — the dominant cost of a multi-minute create. BakeBaseImage runs that
// provisioning ONCE into a local image under a deterministic alias;
// Manager.Create then clones the baked image and skips the install step for
// any stackless create whose (source image, podman) matches what was baked.
//
// The bake reuses installPackages itself — there is no parallel provisioning
// implementation to drift. That works because installPackages is
// user-independent by contract (the per-user podman durability step lives in
// Create): keep it that way, or bakes and full creates will diverge.
//
// Image properties record what a bake contains; the create fast-path matches
// on them, so a bake for a different source image or podman setting is never
// silently reused. Re-bake on a schedule to pick up security updates —
// PublishImage re-points the alias and reaps the replaced image.

const (
	bakedPropBaked         = "containarium.baked"
	bakedPropSource        = "containarium.baked_source"
	bakedPropPodman        = "containarium.baked_podman"
	bakedPropFamily        = "containarium.baked_family"
	bakedPropAt            = "containarium.baked_at"
	bakedPropDaemonVersion = "containarium.baked_daemon_version"
)

// BakedImageAliasFor returns the deterministic local alias for a baked base
// image of the given source image, e.g. "images:ubuntu/24.04" →
// "containarium-base-images-ubuntu-24-04". The alias must stay free of ":"
// and "/" so the incus client resolves it as a LOCAL alias (see
// parseImageSource).
func BakedImageAliasFor(image string) string {
	s := strings.ToLower(image)
	s = strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			return r
		}
		return '-'
	}, s)
	return "containarium-base-" + strings.Trim(s, "-")
}

// bakedImageMatches reports whether a baked image's properties cover a
// create request for (image, enablePodman). Strict equality on both axes: a
// bake for a different source image or without podman must never be
// silently substituted.
func bakedImageMatches(props map[string]string, image string, enablePodman bool) bool {
	return props[bakedPropBaked] == "true" &&
		props[bakedPropSource] == image &&
		props[bakedPropPodman] == strconv.FormatBool(enablePodman)
}

// BakeOptions configures a base-image bake.
type BakeOptions struct {
	// Image is the source image to bake from (same format Create accepts,
	// default images:ubuntu/24.04). OSType, when set, takes precedence —
	// same rule as Create.
	Image        string
	OSType       pb.OSType
	EnablePodman bool
	Verbose      bool
}

// BakeResult reports what a bake produced.
type BakeResult struct {
	Alias       string
	Fingerprint string
	SourceImage string
}

// BakeBaseImage provisions a throwaway container from the source image with
// the exact same installPackages a create would run (no stack, no user),
// then publishes it as a local image under BakedImageAliasFor(source).
// Subsequent stackless creates for the same (image, podman) clone the baked
// image and skip the in-container install entirely.
func (m *Manager) BakeBaseImage(opts BakeOptions) (*BakeResult, error) {
	image := opts.Image
	if opts.OSType != pb.OSType_OS_TYPE_UNSPECIFIED {
		image = ostype.ImageForOSType(opts.OSType)
	}
	if image == "" {
		return nil, fmt.Errorf("bake: an image (or os-type) is required")
	}
	if ostype.IsWindows(opts.OSType) {
		return nil, fmt.Errorf("bake: Windows VMs are not bakeable (no in-container package install to skip)")
	}

	tempName := fmt.Sprintf("containarium-bake-%d", time.Now().Unix())
	if opts.Verbose {
		fmt.Printf("Baking base image from %s (podman=%v) via %s...\n", image, opts.EnablePodman, tempName)
	}

	if err := m.incus.CreateContainer(incus.ContainerConfig{
		Name:          tempName,
		Image:         image,
		EnableNesting: opts.EnablePodman,
	}); err != nil {
		return nil, fmt.Errorf("bake: create %s: %w", tempName, err)
	}
	// The temp container is always removed — the bake's product is the
	// image, never the container.
	defer func() {
		_ = m.incus.DeleteContainer(tempName)
	}()

	if err := m.incus.StartContainer(tempName); err != nil {
		return nil, fmt.Errorf("bake: start %s: %w", tempName, err)
	}
	if _, err := m.incus.WaitForNetwork(tempName, 60*time.Second); err != nil {
		return nil, fmt.Errorf("bake: network on %s: %w", tempName, err)
	}

	family := ostype.FamilyForOSType(opts.OSType)
	if opts.Verbose {
		fmt.Println("  Provisioning (same install a create runs)...")
	}
	if err := m.installPackages(tempName, opts.EnablePodman, "", nil, "", family); err != nil {
		return nil, fmt.Errorf("bake: provisioning %s: %w", tempName, err)
	}

	if err := m.incus.StopContainer(tempName, true); err != nil {
		return nil, fmt.Errorf("bake: stop %s: %w", tempName, err)
	}

	alias := BakedImageAliasFor(image)
	props := map[string]string{
		bakedPropBaked:         "true",
		bakedPropSource:        image,
		bakedPropPodman:        strconv.FormatBool(opts.EnablePodman),
		bakedPropFamily:        string(family),
		bakedPropAt:            time.Now().UTC().Format(time.RFC3339),
		bakedPropDaemonVersion: version.GetVersion(),
	}
	if opts.Verbose {
		fmt.Printf("  Publishing as %s...\n", alias)
	}
	fingerprint, err := m.incus.PublishImage(tempName, alias, props)
	if err != nil {
		return nil, fmt.Errorf("bake: publish: %w", err)
	}
	return &BakeResult{Alias: alias, Fingerprint: fingerprint, SourceImage: image}, nil
}
