package sshauthz

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tg123/sshpiper/libplugin"
)

// User authorization must not make an unpinned backend identity acceptable.
func TestRouterRejectsMissingBackendHostPin(t *testing.T) {
	f := newRouterFixture(t, "")
	data, err := os.ReadFile(f.config)
	if err != nil {
		t.Fatal(err)
	}
	data = []byte(strings.ReplaceAll(string(data), "      known_hosts: "+filepath.Join(f.dir, "known_hosts")+"\n", ""))
	if err := os.WriteFile(f.config, data, 0o600); err != nil {
		t.Fatal(err)
	}
	up, err := NewRouter(f.config).Route(&libplugin.ConnMeta{UserName: "alice"}, f.alice.PublicKey().Marshal())
	if err == nil || up != nil {
		t.Fatalf("router accepted an upstream with no trusted host keys: upstream=%v err=%v", up, err)
	}
}

func TestRouterRejectsUnavailableHostPins(t *testing.T) {
	for _, state := range []string{"missing", "empty", "whitespace", "directory"} {
		t.Run(state, func(t *testing.T) {
			f := newRouterFixture(t, "")
			path := filepath.Join(f.dir, "known_hosts")
			var err error
			switch state {
			case "missing":
				err = os.Remove(path)
			case "empty":
				err = os.WriteFile(path, nil, 0o600)
			case "whitespace":
				err = os.WriteFile(path, []byte(" \n\t"), 0o600)
			case "directory":
				if err = os.Remove(path); err == nil {
					err = os.Mkdir(path, 0o700)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			up, err := NewRouter(f.config).Route(&libplugin.ConnMeta{UserName: "alice"}, f.alice.PublicKey().Marshal())
			if err == nil || up != nil {
				t.Fatalf("router accepted %s pins: upstream=%v err=%v", state, up, err)
			}
		})
	}
}
