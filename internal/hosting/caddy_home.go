package hosting

// caddyHomeDir is the Caddy service's state directory. The unprivileged caddy
// user writes the tree under it, so the root chown over it must not follow a
// symlink that user plants (#3669).
const caddyHomeDir = "/var/lib/caddy"

// CaddyHomeChownArgs returns the argv that hands the Caddy home to the caddy
// user. -h makes the recursive chown act on a symlink itself rather than its
// target. The host and the Caddy container both run this same argv.
func CaddyHomeChownArgs() []string {
	return caddyHomeChownArgs(caddyHomeDir, "caddy:caddy")
}

func caddyHomeChownArgs(dir, owner string) []string {
	return []string{"chown", "-R", "-h", owner, dir}
}
