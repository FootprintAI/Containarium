package sshsession

import (
	"os"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// targetConfig mirrors just the shape of the sshpiper config.yaml this
// sentinel's own keysync (internal/sentinel/keysync.go's
// renderSSHPiperConfig) generates — one pipe per username, no groups or
// regex matching — since that is the only config.yaml this resolver ever
// has to read. It is intentionally not a full model of everything the
// yaml plugin's schema allows.
type targetConfig struct {
	Pipes []struct {
		From []struct {
			Username string `yaml:"username"`
		} `yaml:"from"`
		To struct {
			Host string `yaml:"host"`
		} `yaml:"to"`
	} `yaml:"pipes"`
}

// TargetResolver maps a login username to the backend/container endpoint
// (host:port) the sentinel's sshpiper config currently routes it to, by
// re-reading the same config.yaml keysync generates. Re-reading the file
// — rather than sharing in-process state with the keysync loop — keeps
// the session-record plugin (a separate OS process; see plugin.go and
// internal/cmd/sentinel_ssh_session_plugin.go) independent of whatever
// process happens to be running keysync.
type TargetResolver struct {
	configPath string

	mu      sync.Mutex
	modTime time.Time
	byLogin map[string]string
}

// NewTargetResolver builds a resolver reading configPath on demand.
func NewTargetResolver(configPath string) *TargetResolver {
	return &TargetResolver{configPath: configPath}
}

// Resolve returns the target endpoint config.yaml currently routes login
// to, or "" if there is no matching pipe (including: the file does not
// exist yet, or is not valid YAML). Best-effort by design: an audit
// record with an empty target is far better than one that blocks the SSH
// session it is trying to observe, so Resolve never returns an error.
func (r *TargetResolver) Resolve(login string) string {
	r.mu.Lock()
	defer r.mu.Unlock()

	fi, err := os.Stat(r.configPath)
	if err != nil {
		return ""
	}

	if r.byLogin == nil || !fi.ModTime().Equal(r.modTime) {
		if data, err := os.ReadFile(r.configPath); err == nil {
			var cfg targetConfig
			if yaml.Unmarshal(data, &cfg) == nil {
				byLogin := make(map[string]string, len(cfg.Pipes))
				for _, p := range cfg.Pipes {
					for _, f := range p.From {
						if f.Username != "" {
							byLogin[f.Username] = p.To.Host
						}
					}
				}
				r.byLogin = byLogin
				r.modTime = fi.ModTime()
			}
		}
	}

	return r.byLogin[login]
}
