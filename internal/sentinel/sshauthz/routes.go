package sshauthz

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

const DefaultRoutesFile = "/etc/sshpiper/authz-backends.json"

// Routes is the non-secret snapshot keysync publishes for the separate plugin
// process. Backend IDs are explicit: neither SSH targets nor HTTP addresses
// are treated as interchangeable cache identities.
type Routes struct {
	Logins      map[string]string `json:"logins"`
	BackendURLs map[string]string `json:"backend_urls"`
}

// WriteRoutes atomically replaces the snapshot. Readers never retain stale
// data after removal, a parse failure or a partial update.
func WriteRoutes(path string, routes Routes) error {
	data, err := json.Marshal(routes)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".authz-routes-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }()
	if _, err = f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// FileBackendResolver re-reads the routing snapshot on each lookup, so backend
// changes do not require restarting sshpiperd. It never guesses an HTTP port
// from an SSH endpoint and never falls back to a stale snapshot on errors.
type FileBackendResolver struct{ Path string }

func (r FileBackendResolver) load() (Routes, error) {
	var routes Routes
	data, err := os.ReadFile(r.Path)
	if err != nil {
		return routes, err
	}
	err = json.Unmarshal(data, &routes)
	return routes, err
}
func (r FileBackendResolver) BackendForLogin(login string) (string, bool) {
	if login == "" {
		return "", false
	}
	routes, err := r.load()
	if err != nil {
		return "", false
	}
	id, ok := routes.Logins[login]
	return id, ok && id != ""
}
func (r FileBackendResolver) BackendURL(id string) (string, error) {
	routes, err := r.load()
	if err != nil {
		return "", fmt.Errorf("read SSH authz routing: %w", err)
	}
	u, ok := routes.BackendURLs[id]
	if !ok || u == "" {
		return "", fmt.Errorf("SSH authz backend %q has no daemon URL", id)
	}
	return u, nil
}
