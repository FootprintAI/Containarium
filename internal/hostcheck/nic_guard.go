package hostcheck

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"sort"
	"strings"
)

// NICGuardProbe is what the tenant-isolation posture check reads from the
// host, injected so the check is testable without Incus:
//   - the Incus firewall driver and whether the network_bridge_acl_devices
//     API extension is present (both guards need them),
//   - the running tenant containers whose eth0 carries no
//     containarium-tenant-* ACL (unguarded), and the count that do.
type NICGuardProbe func() (nicGuardFacts, error)

type nicGuardFacts struct {
	firewallDriver string
	hasExtension   bool
	guarded        int
	unguarded      []string
}

const (
	nicGuardRequiredDriver    = "nftables"
	nicGuardRequiredExtension = "network_bridge_acl_devices"
	nicGuardACLPrefix         = "containarium-tenant-"
)

// nicGuardCheck is the tenant ↔ tenant boundary as the host shows it
// (docs/architecture/tenant-network-guard.md): read from Incus itself, not
// from the daemon's own status, so a daemon that believes it is guarding
// and a host that is not disagree visibly. Red when the host cannot carry
// bridge NIC ACLs, or when any running tenant container has no tenant ACL
// on its NIC.
func nicGuardCheck(p posturePaths) Check {
	c := Check{Name: "tenant containers carry a tenant-guard NIC ACL (tenant ↔ tenant isolation)"}
	if p.nicGuardProbe == nil {
		c.Detail = "could not determine: no probe configured"
		return c
	}
	f, err := p.nicGuardProbe()
	if err != nil {
		c.Detail = fmt.Sprintf("could not determine: %v", err)
		return c
	}
	var problems []string
	if f.firewallDriver != nicGuardRequiredDriver {
		problems = append(problems, fmt.Sprintf("incus firewall driver is %q (need %s)", f.firewallDriver, nicGuardRequiredDriver))
	}
	if !f.hasExtension {
		problems = append(problems, "incus lacks the "+nicGuardRequiredExtension+" API extension (Incus 6.9+; the README's Zabbly build has it)")
	}
	if len(f.unguarded) > 0 {
		sort.Strings(f.unguarded)
		shown := f.unguarded
		if len(shown) > 5 {
			shown = append(append([]string(nil), shown[:5]...), fmt.Sprintf("… %d more", len(f.unguarded)-5))
		}
		problems = append(problems, fmt.Sprintf("%d running tenant container(s) without a %s* ACL on eth0: %s", len(f.unguarded), nicGuardACLPrefix, strings.Join(shown, ", ")))
	}
	if len(problems) > 0 {
		c.Detail = strings.Join(problems, "; ") + " — fix: install Incus from the Zabbly repository with the nftables driver and leave CONTAINARIUM_TENANT_GUARD unset (enforce); `containarium network-guard status --server <daemon>` shows the daemon's view"
		return c
	}
	c.OK = true
	c.Detail = fmt.Sprintf("driver %s, %s present, %d tenant container(s) guarded, 0 unguarded", f.firewallDriver, nicGuardRequiredExtension, f.guarded)
	return c
}

// defaultNICGuardProbe reads Incus through its CLI: `incus query /1.0` for
// the driver and extensions, `incus list` for running containers and their
// expanded eth0 device (security.acls).
func defaultNICGuardProbe() (nicGuardFacts, error) {
	var f nicGuardFacts
	raw, err := exec.Command("incus", "query", "/1.0").Output()
	if err != nil {
		return f, fmt.Errorf("incus query /1.0: %w", err)
	}
	var server struct {
		APIExtensions []string `json:"api_extensions"`
		Environment   struct {
			Firewall string `json:"firewall"`
		} `json:"environment"`
	}
	if err := json.Unmarshal(raw, &server); err != nil {
		return f, fmt.Errorf("parse incus server info: %w", err)
	}
	f.firewallDriver = server.Environment.Firewall
	for _, e := range server.APIExtensions {
		if e == nicGuardRequiredExtension {
			f.hasExtension = true
			break
		}
	}
	raw, err = exec.Command("incus", "list", "--format", "json").Output()
	if err != nil {
		return f, fmt.Errorf("incus list: %w", err)
	}
	var instances []struct {
		Name            string                       `json:"name"`
		Status          string                       `json:"status"`
		Config          map[string]string            `json:"config"`
		ExpandedDevices map[string]map[string]string `json:"expanded_devices"`
	}
	if err := json.Unmarshal(raw, &instances); err != nil {
		return f, fmt.Errorf("parse incus list: %w", err)
	}
	for _, in := range instances {
		if in.Status != "Running" || isCoreContainerName(in.Name) {
			continue
		}
		acls := in.ExpandedDevices["eth0"]["security.acls"]
		if strings.Contains(acls, nicGuardACLPrefix) {
			f.guarded++
		} else {
			f.unguarded = append(f.unguarded, in.Name)
		}
	}
	return f, nil
}

// isCoreContainerName mirrors the name convention the scripts use for
// core-role containers; roles are also labelled, but the name is what a
// host-level check can read without the daemon.
func isCoreContainerName(name string) bool {
	return strings.HasPrefix(name, "containarium-core-") || strings.HasPrefix(name, "core-")
}
