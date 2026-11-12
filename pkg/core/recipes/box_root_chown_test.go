package recipes

import (
	"os"
	"strings"
	"testing"
)

// Root-run chowns of paths the box user owns must not follow a symlink (#3670).
func TestSlidesChownRefusesSymlinkAndDoesNotFollow(t *testing.T) {
	data, err := embeddedFS.ReadFile("recipes.yaml")
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	if !strings.Contains(s, `[ ! -L "$SLIDES_HOME" ]`) {
		t.Error("slides step does not refuse a symlink at $SLIDES_HOME")
	}
	if !strings.Contains(s, `chown -h "$BOX_UID:$BOX_GID" "$SLIDES_HOME"`) {
		t.Error("slides chown does not use -h")
	}
}

func TestKubeflowManifestChownUsesNoFollow(t *testing.T) {
	b, err := os.ReadFile("../stacks/stacks.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "chown -R -h ") || !strings.Contains(string(b), "/opt/kubeflow-manifests") {
		t.Error("kubeflow manifests chown does not use -h")
	}
}
