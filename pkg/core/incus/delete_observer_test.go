package incus

import (
	"errors"
	"testing"

	incusclient "github.com/lxc/incus/v7/client"
	"github.com/lxc/incus/v7/shared/api"
)

// fakeDeleteServer serves one instance and deletes it.
type fakeDeleteServer struct {
	incusclient.InstanceServer
	inst      *api.Instance
	deleteErr error
	deleted   []string
}

func (f *fakeDeleteServer) GetInstance(string) (*api.Instance, string, error) {
	if f.inst == nil {
		return nil, "", api.StatusErrorf(404, "Instance not found")
	}
	cp := *f.inst
	return &cp, "etag", nil
}

func (f *fakeDeleteServer) DeleteInstance(name string) (incusclient.Operation, error) {
	if f.deleteErr != nil {
		return nil, f.deleteErr
	}
	f.deleted = append(f.deleted, name)
	return fakeOp{}, nil
}

// TestDeleteContainer_TellsTheDeleteObservers (#2835 review, item 3): every
// delete that goes through the Incus client, whichever server path issued it
// (DeleteContainer, the cloud actuator, sandboxes), tells the registered
// observers which box went and which instance it was, so the process
// responder can close that instance's action and only that one.
func TestDeleteContainer_TellsTheDeleteObservers(t *testing.T) {
	type seen struct{ name, id string }
	var got []seen
	remove := OnContainerDeleted(func(name, instanceID string) { got = append(got, seen{name, instanceID}) })
	defer remove()

	srv := &fakeDeleteServer{inst: &api.Instance{Name: "box-a", InstancePut: api.InstancePut{Config: map[string]string{"volatile.uuid": "uuid-1"}}}}
	c := &Client{server: srv}
	if err := c.DeleteContainer("box-a"); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != (seen{"box-a", "uuid-1"}) {
		t.Fatalf("observers saw %v, want [box-a uuid-1]", got)
	}

	srv.deleteErr = errors.New("incus: busy")
	if err := c.DeleteContainer("box-a"); err == nil {
		t.Fatal("want the delete error")
	}
	if len(got) != 1 {
		t.Errorf("a failed delete was reported: %v", got)
	}

	remove()
	srv.deleteErr = nil
	if err := c.DeleteContainer("box-a"); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Errorf("a removed observer was still told: %v", got)
	}
}

// A panicking observer must not fail the delete or stop the others.
func TestDeleteContainer_ObserverPanicIsContained(t *testing.T) {
	removeBad := OnContainerDeleted(func(string, string) { panic("observer bug") })
	defer removeBad()
	called := false
	removeGood := OnContainerDeleted(func(string, string) { called = true })
	defer removeGood()
	c := &Client{server: &fakeDeleteServer{inst: &api.Instance{Name: "box-a"}}}
	if err := c.DeleteContainer("box-a"); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Error("the other observer was not told")
	}
}
