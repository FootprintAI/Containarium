package incus

import (
	"errors"
	"reflect"
	"sort"
	"sync/atomic"
	"testing"
	"time"

	incusclient "github.com/lxc/incus/v7/client"
	"github.com/lxc/incus/v7/shared/api"
)

// fakeListServer implements the instance-listing half of incus.InstanceServer
// and counts the requests each list costs. The embedded interface is nil: an
// unstubbed call panics instead of returning a zero value.
type fakeListServer struct {
	incusclient.InstanceServer

	instances []api.InstanceFull
	fullErr   error

	names, gets, states, fulls atomic.Int32
}

func (f *fakeListServer) GetInstanceNames(api.InstanceType) ([]string, error) {
	f.names.Add(1)
	out := make([]string, 0, len(f.instances))
	for _, i := range f.instances {
		out = append(out, i.Name)
	}
	return out, nil
}

func (f *fakeListServer) find(name string) (*api.InstanceFull, error) {
	for i := range f.instances {
		if f.instances[i].Name == name {
			return &f.instances[i], nil
		}
	}
	return nil, errors.New("not found")
}

func (f *fakeListServer) GetInstance(name string) (*api.Instance, string, error) {
	f.gets.Add(1)
	i, err := f.find(name)
	if err != nil {
		return nil, "", err
	}
	inst := i.Instance
	return &inst, "", nil
}

func (f *fakeListServer) GetInstanceState(name string) (*api.InstanceState, string, error) {
	f.states.Add(1)
	i, err := f.find(name)
	if err != nil {
		return nil, "", err
	}
	return i.State, "", nil
}

func (f *fakeListServer) GetInstancesFull(api.InstanceType) ([]api.InstanceFull, error) {
	f.fulls.Add(1)
	if f.fullErr != nil {
		return nil, f.fullErr
	}
	return f.instances, nil
}

func listFixture() []api.InstanceFull {
	created := time.Unix(1_700_000_000, 0).UTC()
	return []api.InstanceFull{
		{
			Instance: api.Instance{
				Name: "a-box", Status: "Running", Type: "container", CreatedAt: created,
				InstancePut: api.InstancePut{
					Config: map[string]string{
						TenantLabelKey: "a-tenant", "limits.memory": "2GB", "limits.cpu": "2",
						"user.containarium.label.team": "x",
					},
					Devices: map[string]map[string]string{"root": {"type": "disk", "size": "10GB"}},
				},
			},
			State: &api.InstanceState{
				Pid: 4242,
				Network: map[string]api.InstanceStateNetwork{
					"eth0": {Addresses: []api.InstanceStateNetworkAddress{{Family: "inet", Address: "192.0.2.10", Scope: "global"}}},
				},
			},
		},
		{
			Instance: api.Instance{
				Name: "b-box", Status: "Stopped", Type: "container", CreatedAt: created,
				InstancePut:     api.InstancePut{Config: map[string]string{TenantLabelKey: "b-tenant"}},
				ExpandedDevices: map[string]map[string]string{"root": {"type": "disk", "size": "5GB"}},
			},
			State: &api.InstanceState{},
		},
	}
}

func sortedByName(in []ContainerInfo) []ContainerInfo {
	sort.Slice(in, func(i, j int) bool { return in[i].Name < in[j].Name })
	return in
}

// #3050: the reconcile loop's list is one Incus request, not 1 + 2N, and maps
// every instance exactly as ListContainers does.
func TestListContainersFull_OneRequestSameResult(t *testing.T) {
	f := &fakeListServer{instances: listFixture()}
	c := &Client{server: f}

	perInstance, err := c.ListContainers()
	if err != nil {
		t.Fatal(err)
	}
	if got, want := int(f.gets.Load()+f.states.Load()), 2*len(f.instances); got != want {
		t.Fatalf("setup: ListContainers made %d per-instance requests, want %d", got, want)
	}
	f.names.Store(0)
	f.gets.Store(0)
	f.states.Store(0)

	full, err := c.ListContainersFull()
	if err != nil {
		t.Fatalf("ListContainersFull: %v", err)
	}
	if n, g, s, fl := f.names.Load(), f.gets.Load(), f.states.Load(), f.fulls.Load(); fl != 1 || n+g+s != 0 {
		t.Fatalf("ListContainersFull made names=%d gets=%d states=%d full=%d requests, want exactly one full list", n, g, s, fl)
	}
	if !reflect.DeepEqual(sortedByName(full), sortedByName(perInstance)) {
		t.Fatalf("ListContainersFull differs from ListContainers:\n full: %+v\n per-instance: %+v", full, perInstance)
	}
	if full[0].IPAddress != "192.0.2.10" || full[0].Pid != 4242 {
		t.Fatalf("running box state not mapped: ip=%q pid=%d", full[0].IPAddress, full[0].Pid)
	}
}

// A failed full list fails the list: the caller (one reconcile pass) skips
// and the next pass retries, rather than acting on a partial view.
func TestListContainersFull_ErrorFailsTheList(t *testing.T) {
	f := &fakeListServer{instances: listFixture(), fullErr: errors.New("incus down")}
	c := &Client{server: f}
	if got, err := c.ListContainersFull(); err == nil {
		t.Fatalf("want an error, got %+v", got)
	}
}
