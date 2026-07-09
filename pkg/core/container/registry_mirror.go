package container

import (
	"fmt"
	"os"
	"strings"
)

// Warm-image cache via bring-your-own registry mirror (#908).
//
// Every box has its own ephemeral podman storage, so a fresh box re-pulls its
// images from scratch — a multi-GB image over the WAN can blow a programmatic
// consumer's readiness budget (the OpenHands SDK gives 300s; a ~3.8GB pull took
// ~17min on a loaded host). Pull-through caching is a commodity, so Containarium
// does NOT run a registry: it ships only the thin box-side wiring. An operator
// points boxes at a mirror they already run (registry:2 proxy, Harbor, zot, a
// cloud AR mirror) via CONTAINARIUM_REGISTRY_MIRRORS, and box provisioning drops
// a non-destructive registries.conf.d entry so the box's podman resolves those
// upstreams through the LAN mirror first. First box pulls through (WAN, once);
// every box after pulls over the LAN. Fails safe: no config -> no drop-in ->
// today's behavior; mirror down -> podman falls back to the upstream.
//
// See docs/WARM-IMAGE-CACHE-DESIGN.md.

// envRegistryMirrors is the host/daemon env var declaring registry mirrors as a
// comma-separated list of `upstream=mirror` pairs, e.g.
//
//	CONTAINARIUM_REGISTRY_MIRRORS="docker.io=http://mirror.lan:5000,ghcr.io=http://mirror.lan:5000"
//
// The mirror may carry a scheme: `http://` marks it insecure (plain-HTTP LAN
// mirror); `https://` or a bare host:port is treated as secure.
const envRegistryMirrors = "CONTAINARIUM_REGISTRY_MIRRORS"

// registryMirrorsPath is the box-side drop-in. podman merges every file in
// registries.conf.d over the base registries.conf, so this never clobbers the
// image's defaults (unqualified-search-registries etc.).
const registryMirrorsPath = "/etc/containers/registries.conf.d/00-containarium-mirrors.conf"

// registryMirrorsDir is the drop-in directory (podman ships it, but a minimal
// base image may not — we mkdir -p before writing).
const registryMirrorsDir = "/etc/containers/registries.conf.d"

// RegistryMirror is one upstream->mirror redirect for the box's podman.
type RegistryMirror struct {
	Upstream string // e.g. "docker.io", "ghcr.io"
	Location string // mirror host[:port], no scheme, e.g. "mirror.lan:5000"
	Insecure bool   // plain-HTTP mirror (no TLS)
}

// defaultRegistryMirrors reads the configured mirrors from the environment.
func defaultRegistryMirrors() []RegistryMirror {
	return parseRegistryMirrors(os.Getenv(envRegistryMirrors))
}

// parseRegistryMirrors parses the CONTAINARIUM_REGISTRY_MIRRORS value. Malformed
// entries (no '=', empty upstream/mirror) are skipped rather than failing — a
// bad env var must not brick box creation.
func parseRegistryMirrors(s string) []RegistryMirror {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	var out []RegistryMirror
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		up, mir, ok := strings.Cut(part, "=")
		up = strings.TrimSpace(up)
		mir = strings.TrimSpace(mir)
		if !ok || up == "" || mir == "" {
			continue
		}
		insecure := false
		if rest, found := strings.CutPrefix(mir, "http://"); found {
			mir, insecure = rest, true
		} else if rest, found := strings.CutPrefix(mir, "https://"); found {
			mir = rest
		}
		mir = strings.Trim(strings.TrimRight(mir, "/"), " ")
		if mir == "" {
			continue
		}
		out = append(out, RegistryMirror{Upstream: up, Location: mir, Insecure: insecure})
	}
	return out
}

// renderMirrorsConf renders the registries.conf.d drop-in (containers-registries
// v2 TOML). One [[registry]] block per upstream, each with a single mirror.
func renderMirrorsConf(mirrors []RegistryMirror) string {
	var b strings.Builder
	b.WriteString("# Managed by Containarium (#908) — registry pull-through mirrors.\n")
	b.WriteString("# Boxes resolve these upstreams via the operator-provided mirror\n")
	b.WriteString("# first, falling back to the upstream on a miss or mirror outage.\n")
	for _, m := range mirrors {
		b.WriteString("\n[[registry]]\n")
		fmt.Fprintf(&b, "location = %q\n", m.Upstream)
		b.WriteString("[[registry.mirror]]\n")
		fmt.Fprintf(&b, "location = %q\n", m.Location)
		if m.Insecure {
			b.WriteString("insecure = true\n")
		}
	}
	return b.String()
}

// writeRegistryMirrors installs the mirror drop-in into a box. No-op when no
// mirror is configured. Returns an error only on a substrate failure; the
// caller treats it as best-effort (a good box must not be lost over mirror
// config — podman still pulls upstream).
func (m *Manager) writeRegistryMirrors(containerName string) error {
	if len(m.mirrors) == 0 {
		return nil
	}
	if err := m.incus.Exec(containerName, []string{"mkdir", "-p", registryMirrorsDir}); err != nil {
		return fmt.Errorf("registry-mirror: mkdir %s: %w", registryMirrorsDir, err)
	}
	if err := m.incus.WriteFile(containerName, registryMirrorsPath, []byte(renderMirrorsConf(m.mirrors)), "0644"); err != nil {
		return fmt.Errorf("registry-mirror: write %s: %w", registryMirrorsPath, err)
	}
	return nil
}
