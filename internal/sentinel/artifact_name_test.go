package sentinel

import "testing"

// TestArtifactNameGate pins #1779 / the design doc's "Artifact-name gate
// (Phase 1)": the fleet's self-update chain must ask for and serve the
// containariumd artifact from release N on. A regression here silently
// re-widens the client/server split hole the whole design exists to close
// (the sentinel would serve, and backends would install, a binary that no
// longer has the daemon in it once containarium-* switches to the client
// build in Phase 2).
func TestArtifactNameGate(t *testing.T) {
	if releaseBinaryName != "containariumd-linux-amd64" {
		t.Errorf("releaseBinaryName = %q, want %q", releaseBinaryName, "containariumd-linux-amd64")
	}
	if defaultBinaryPath != "/usr/local/bin/containariumd" {
		t.Errorf("defaultBinaryPath = %q, want %q", defaultBinaryPath, "/usr/local/bin/containariumd")
	}
}
