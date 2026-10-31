package sshauthz

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/tg123/sshpiper/libplugin"
	"github.com/tg123/sshpiper/libplugin/skel"
	"gopkg.in/yaml.v3"
)

// Router returns the upstream sshpiper's yaml plugin would return for an
// offered public key or certificate. It runs the yaml plugin's own checker,
// libplugin/skel (certificate validity, CA match, authorized_keys match and
// upstream construction), over the config.yaml keysync generates, so enforce
// mode can route a connection itself instead of deferring to yaml (#2629).
type Router struct {
	path string
	skel *skel.SkelPlugin
}

func NewRouter(configPath string) *Router {
	r := &Router{path: configPath}
	r.skel = skel.NewSkelPlugin(r.listPipes)
	return r
}

// Route returns the upstream, or an error when no pipe verifies the key. Like
// the yaml plugin, it re-reads config.yaml on every call.
func (r *Router) Route(conn libplugin.ConnMetadata, publicKey []byte) (*libplugin.Upstream, error) {
	return r.skel.PublicKeyCallback(conn, publicKey)
}

// routerConfig is the subset of the yaml plugin's schema that keysync's
// renderSSHPiperConfig writes. Decoding is strict: any other field (regex or
// group matching, inline *_data, password) fails the load, so the
// router refuses rather than route differently from the yaml plugin.
type routerConfig struct {
	Version string `yaml:"version"`
	Pipes   []struct {
		From []routerFrom `yaml:"from"`
		To   routerTo     `yaml:"to"`
	} `yaml:"pipes"`
}

type routerFrom struct {
	Username          string   `yaml:"username"`
	AuthorizedKeys    []string `yaml:"authorized_keys"`
	TrustedUserCAKeys []string `yaml:"trusted_user_ca_keys"`
}

type routerTo struct {
	Host     string `yaml:"host"`
	Username string `yaml:"username"`
	// Accept legacy configs, but this flag never bypasses required host pins.
	IgnoreHostkey bool   `yaml:"ignore_hostkey"`
	PrivateKey    string `yaml:"private_key"`
	KnownHosts    string `yaml:"known_hosts"`
}

func (r *Router) listPipes(libplugin.ConnMetadata) ([]skel.SkelPipe, error) {
	fi, err := os.Stat(r.path)
	if err != nil {
		return nil, err
	}
	// The same rule as the yaml plugin's checkPerm.
	if fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("ssh authz router: %s's perm is too open", r.path)
	}
	data, err := os.ReadFile(r.path)
	if err != nil {
		return nil, err
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var cfg routerConfig
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("ssh authz router: %s: %w", r.path, err)
	}
	dir := filepath.Dir(r.path)
	pipes := make([]skel.SkelPipe, 0, len(cfg.Pipes))
	for i := range cfg.Pipes {
		p := &cfg.Pipes[i]
		pipes = append(pipes, routerPipe{dir: dir, from: p.From, to: &p.To})
	}
	return pipes, nil
}

type routerPipe struct {
	dir  string
	from []routerFrom
	to   *routerTo
}

// From lists the public-key froms. The yaml plugin treats a from with neither
// key list as a password from, which never verifies a public key.
func (p routerPipe) From() []skel.SkelPipeFrom {
	var froms []skel.SkelPipeFrom
	for i := range p.from {
		if f := &p.from[i]; len(f.AuthorizedKeys)+len(f.TrustedUserCAKeys) > 0 {
			froms = append(froms, routerKeyFrom{dir: p.dir, from: f, to: p.to})
		}
	}
	return froms
}

type routerKeyFrom struct {
	dir  string
	from *routerFrom
	to   *routerTo
}

func (f routerKeyFrom) MatchConn(conn libplugin.ConnMetadata) (skel.SkelPipeTo, error) {
	if f.from.Username == "" || f.from.Username != conn.User() {
		return nil, nil
	}
	if f.to.PrivateKey == "" {
		return nil, errors.New("ssh authz router: pipe has no private_key")
	}
	user := f.to.Username
	if user == "" {
		user = conn.User()
	}
	return routerTarget{dir: f.dir, to: f.to, user: user}, nil
}

func (f routerKeyFrom) AuthorizedKeys(libplugin.ConnMetadata) ([]byte, error) {
	return readFiles(f.dir, f.from.AuthorizedKeys)
}

func (f routerKeyFrom) TrustedUserCAKeys(libplugin.ConnMetadata) ([]byte, error) {
	return readFiles(f.dir, f.from.TrustedUserCAKeys)
}

type routerTarget struct {
	dir  string
	to   *routerTo
	user string
}

func (t routerTarget) Host(libplugin.ConnMetadata) string { return t.to.Host }
func (t routerTarget) User(libplugin.ConnMetadata) string { return t.user }
func (t routerTarget) KnownHosts(libplugin.ConnMetadata) ([]byte, error) {
	if t.to.KnownHosts == "" {
		return nil, errors.New("ssh authz router: pipe has no known_hosts")
	}
	data, err := readFiles(t.dir, []string{t.to.KnownHosts})
	if err != nil {
		return nil, err
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, errors.New("ssh authz router: known_hosts is empty")
	}
	return data, nil
}

func (t routerTarget) PrivateKey(libplugin.ConnMetadata) ([]byte, []byte, error) {
	key, err := readFiles(t.dir, []string{t.to.PrivateKey})
	return key, nil, err
}

// readFiles joins files with a newline, as the yaml plugin does. Relative
// paths resolve against the config's directory. Placeholders such as
// $DOWNSTREAM_USER are refused: keysync never writes them.
func readFiles(dir string, paths []string) ([]byte, error) {
	var parts [][]byte
	for _, path := range paths {
		if path == "" {
			continue
		}
		if strings.Contains(path, "$") {
			return nil, fmt.Errorf("ssh authz router: placeholder in %q is not supported", path)
		}
		if !filepath.IsAbs(path) {
			path = filepath.Join(dir, path)
		}
		data, err := os.ReadFile(path) // #nosec G304 -- a path from the root-owned 0600 config.yaml, as the yaml plugin reads it
		if err != nil {
			return nil, err
		}
		parts = append(parts, data)
	}
	return bytes.Join(parts, []byte("\n")), nil
}
