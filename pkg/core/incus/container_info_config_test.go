package incus

import (
	"fmt"
	"testing"

	incusclient "github.com/lxc/incus/v7/client"
	"github.com/lxc/incus/v7/shared/api"
)

// fakeConfigServer serves one instance, by name, with the given config, so
// the container read paths can be checked for the typed fields they build
// from an instance's config keys.
type fakeConfigServer struct {
	incusclient.InstanceServer
	inst api.Instance
}

func (f *fakeConfigServer) GetInstance(string) (*api.Instance, string, error) {
	cp := f.inst
	return &cp, "etag", nil
}

func (f *fakeConfigServer) GetInstanceState(string) (*api.InstanceState, string, error) {
	return &api.InstanceState{}, "etag", nil
}

func (f *fakeConfigServer) GetInstanceNames(api.InstanceType) ([]string, error) {
	return []string{f.inst.Name}, nil
}

func (f *fakeConfigServer) GetInstancesFull(api.InstanceType) ([]api.InstanceFull, error) {
	return []api.InstanceFull{{Instance: f.inst, State: &api.InstanceState{}}}, nil
}

// onlyEntry returns the one entry of a list read, or an error.
func onlyEntry(infos []ContainerInfo, err error) (ContainerInfo, error) {
	if err != nil {
		return ContainerInfo{}, err
	}
	if len(infos) != 1 {
		return ContainerInfo{}, fmt.Errorf("got %d entries, want 1", len(infos))
	}
	return infos[0], nil
}

// TestContainerReadPaths_MapTypedConfigKeys (#3555): every path that builds a
// ContainerInfo from an instance reads the post_start-pending mark (and the
// tool-access level and podman flag) from the instance's config. A skill
// run's reuse path reads the box through GetContainer, so a read missing
// there makes a half-prepared box look prepared again (#3546).
func TestContainerReadPaths_MapTypedConfigKeys(t *testing.T) {
	marked := map[string]string{
		PostStartPendingKey: PostStartPendingValue,
		ToolAccessKey:       ToolAccessBuildTools,
		PodmanEnabledKey:    "false",
	}
	unmarked := map[string]string{PodmanEnabledKey: "true"}

	reads := []struct {
		name string
		read func(c *Client, name string) (ContainerInfo, error)
	}{
		{"GetContainer", func(c *Client, name string) (ContainerInfo, error) {
			info, err := c.GetContainer(name)
			if err != nil {
				return ContainerInfo{}, err
			}
			return *info, nil
		}},
		{"ListContainers", func(c *Client, _ string) (ContainerInfo, error) {
			return onlyEntry(c.ListContainers())
		}},
		{"ListContainersFull", func(c *Client, _ string) (ContainerInfo, error) {
			return onlyEntry(c.ListContainersFull())
		}},
	}
	for _, r := range reads {
		t.Run(r.name, func(t *testing.T) {
			for _, tc := range []struct {
				name              string
				cfg               map[string]string
				wantPending       bool
				wantToolAccess    string
				wantPodmanEnabled bool
			}{
				{"marked box", marked, true, ToolAccessBuildTools, false},
				{"prepared box", unmarked, false, "", true},
			} {
				c := &Client{server: &fakeConfigServer{inst: api.Instance{Name: "box-container", Status: "Running", InstancePut: api.InstancePut{Config: tc.cfg}}}}
				info, err := r.read(c, "box-container")
				if err != nil {
					t.Fatalf("%s: %v", tc.name, err)
				}
				if info.PostStartPending != tc.wantPending {
					t.Errorf("%s: PostStartPending = %v, want %v", tc.name, info.PostStartPending, tc.wantPending)
				}
				if info.ToolAccess != tc.wantToolAccess {
					t.Errorf("%s: ToolAccess = %q, want %q", tc.name, info.ToolAccess, tc.wantToolAccess)
				}
				if info.PodmanEnabled != tc.wantPodmanEnabled {
					t.Errorf("%s: PodmanEnabled = %v, want %v", tc.name, info.PodmanEnabled, tc.wantPodmanEnabled)
				}
			}
		})
	}
}
