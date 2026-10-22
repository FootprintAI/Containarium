package container

import (
	"strconv"
	"testing"

	"github.com/footprintai/containarium/pkg/core/incus"
)

// TestCreate_PodmanEnabledPersistedAsConfigKey (#2858): the create-time flag is
// stamped in both directions, so a box created with podman off is
// distinguishable from a legacy box that has no key at all.
func TestCreate_PodmanEnabledPersistedAsConfigKey(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	for _, enable := range []bool{true, false} {
		t.Run(strconv.FormatBool(enable), func(t *testing.T) {
			backend := &stagesBackend{}
			m := NewWithBackend(backend)
			opts := stagesOpts()
			opts.EnablePodman = enable
			if _, err := m.Create(opts); err != nil {
				t.Fatalf("Create: %v", err)
			}
			got, ok := backend.createdConfig.ExtraConfig[incus.PodmanEnabledKey]
			if !ok || got != strconv.FormatBool(enable) {
				t.Errorf("ExtraConfig[%q] = %q (present=%v), want %q", incus.PodmanEnabledKey, got, ok, strconv.FormatBool(enable))
			}
		})
	}
}
