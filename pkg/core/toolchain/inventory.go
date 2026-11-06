package toolchain

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Tool sources recorded in a release manifest. The built-in lock writes no
// source field, so an absent value means SourceManaged (#3570).
const (
	SourceManaged = "managed"
	SourceExtra   = "extra"
)

var executableName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// Tool is one inventoried entry of manifest.json.
type Tool struct {
	Name    string   `json:"name"`
	Version string   `json:"version"`
	Source  string   `json:"source"`
	Bin     []string `json:"bin"`
}

// Inventory is the active release's tool list, from manifest.json.
type Inventory struct {
	Release string `json:"release"`
	Arch    string `json:"arch"`
	// ExtraLockSHA256 is the digest of the deployer-supplied extra lock the
	// release was built from; empty when the release has none.
	ExtraLockSHA256 string `json:"extra_lock_sha256"`
	Tools           []Tool `json:"tools"`
}

// ReadInventory reads root's active release manifest.
func ReadInventory(root string) (Inventory, error) {
	if err := CheckRelease(root); err != nil {
		return Inventory{}, err
	}
	path := filepath.Join(root, "current", "manifest.json")
	data, err := os.ReadFile(path) // #nosec G304 -- fixed manifest name under the platform toolchain root
	if err != nil {
		return Inventory{}, fmt.Errorf("read managed toolchain manifest %s: %w", path, err)
	}
	var inv Inventory
	if err := json.Unmarshal(data, &inv); err != nil {
		return Inventory{}, fmt.Errorf("parse managed toolchain manifest %s: %w", path, err)
	}
	for i := range inv.Tools {
		if inv.Tools[i].Source == "" {
			inv.Tools[i].Source = SourceManaged
		}
	}
	return inv, nil
}

// ExtraExecutables lists the command names the extra tools expose in
// current/bin. A name that is not a plain file name is dropped: the manifest
// is root-owned, but these names become paths in a box's /usr/local/bin.
func (i Inventory) ExtraExecutables() []string {
	var names []string
	for _, t := range i.Tools {
		if t.Source != SourceExtra {
			continue
		}
		for _, rel := range t.Bin {
			clean := filepath.Clean(rel)
			if filepath.IsAbs(clean) || strings.Contains(clean, "..") {
				continue
			}
			if name := filepath.Base(clean); executableName.MatchString(name) {
				names = append(names, name)
			}
		}
	}
	return names
}
