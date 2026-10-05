package hostcheck

// PlatformCPUWeight is the systemd CPUWeight= the platform's own daemons
// run at (#2284). systemd's default — and therefore every tenant instance's
// effective weight — is 100; 10× that keeps `incusd` and the containarium
// daemon scheduling when ~70 tenants saturate the host, without starving
// tenants outright the way a quota or an absolute priority would.
//
// No build constraint on this file: the Windows cmd build references the
// constant from the unit-template tests even though the check itself is
// Linux-only.
const PlatformCPUWeight = 1000

// PlatformCPUUnits are the systemd units that must carry PlatformCPUWeight:
// incusd (installed from the distro / Zabbly package, so its weight lands as
// a drop-in) and the containarium daemon (whose generated unit carries it
// inline). Order is the order `doctor` reports them in.
var PlatformCPUUnits = []string{"incus.service", "containarium.service"}
