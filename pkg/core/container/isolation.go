package container

import (
	"fmt"
	"strings"

	incusapi "github.com/lxc/incus/v7/shared/api"

	"github.com/footprintai/containarium/pkg/core/ostype"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// resolveInstanceType decides whether a create produces an LXC container
// or a QEMU/KVM VM from the (os_type, isolation) pair (#2196).
//
// UNSPECIFIED isolation is exactly the pre-#2196 rule — Windows is a VM,
// everything else a container — so existing callers are byte-for-byte
// unaffected. An explicit VM is honored for any OS; an explicit CONTAINER
// is refused for Windows, which has no container image.
func resolveInstanceType(osType pb.OSType, isolation pb.IsolationType) (incusapi.InstanceType, error) {
	switch isolation {
	case pb.IsolationType_ISOLATION_TYPE_VM:
		return incusapi.InstanceTypeVM, nil
	case pb.IsolationType_ISOLATION_TYPE_CONTAINER:
		if ostype.IsWindows(osType) {
			return "", fmt.Errorf("os_type %s cannot run as a container: Windows requires isolation=vm", osType)
		}
		return incusapi.InstanceTypeContainer, nil
	default:
		if ostype.IsWindows(osType) {
			return incusapi.InstanceTypeVM, nil
		}
		return incusapi.InstanceTypeContainer, nil
	}
}

// vmImageFor returns the image to boot a Linux VM from. The images: remote
// publishes a "/cloud" variant of every alias that carries cloud-init,
// which installPackages waits on, so a plain images: alias is retargeted
// to it. Anything else — a local: image, a baked alias, an alias that
// already names the variant — is the caller's explicit choice and passes
// through.
func vmImageFor(image string) string {
	if !strings.HasPrefix(image, "images:") || strings.HasSuffix(image, "/cloud") {
		return image
	}
	return image + "/cloud"
}
