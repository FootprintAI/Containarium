package incus

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	incusclient "github.com/lxc/incus/v7/client"
	"github.com/lxc/incus/v7/shared/api"
)

// hangOp is an Incus operation that never completes (#3470). WaitContext
// honours ctx the way the real client does; Wait blocks forever, which is
// what every unbounded wait on main does with a wedged operation.
type hangOp struct{ incusclient.Operation }

func (hangOp) Wait() error { select {} }

func (hangOp) WaitContext(ctx context.Context) error {
	<-ctx.Done()
	return ctx.Err()
}

func (hangOp) Get() api.Operation { return api.Operation{} }

// deafOp never completes and ignores ctx entirely, so only the helper's own
// select bounds it.
type deafOp struct{ incusclient.Operation }

func (deafOp) Wait() error                       { select {} }
func (deafOp) WaitContext(context.Context) error { select {} }

// funcOp completes however wait says.
type funcOp struct {
	incusclient.Operation
	wait func(ctx context.Context) error
}

func (o funcOp) Wait() error                           { return o.wait(context.Background()) }
func (o funcOp) WaitContext(ctx context.Context) error { return o.wait(ctx) }
func (funcOp) Get() api.Operation                      { return api.Operation{} }

// within fails the test if f has not returned after limit.
func within(t *testing.T, limit time.Duration, f func() error) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- f() }()
	select {
	case err := <-done:
		return err
	case <-time.After(limit):
		t.Fatalf("wait still blocked after %s: not bounded by a deadline", limit)
		return nil
	}
}

func assertTimeout(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, ErrOperationTimeout) {
		t.Fatalf("want ErrOperationTimeout, got %v", err)
	}
	var te *OperationTimeoutError
	if !errors.As(err, &te) {
		t.Fatalf("want an *OperationTimeoutError in the chain, got %T: %v", err, err)
	}
}

func TestWaitOp_NeverCompletingOperationTimesOut(t *testing.T) {
	for name, op := range map[string]OperationWaiter{"honours ctx": hangOp{}, "ignores ctx": deafOp{}} {
		t.Run(name, func(t *testing.T) {
			err := within(t, 2*time.Second, func() error {
				return waitOp(context.Background(), op, 30*time.Millisecond)
			})
			assertTimeout(t, err)
			var te *OperationTimeoutError
			_ = errors.As(err, &te)
			if te.Timeout != 30*time.Millisecond {
				t.Errorf("timeout error should name the applied default, got %s", te.Timeout)
			}
		})
	}
}

func TestWaitOp_CallerDeadlineIsRespected(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	err := within(t, 2*time.Second, func() error { return waitOp(ctx, hangOp{}, time.Hour) })
	assertTimeout(t, err)
}

// A caller's deadline replaces the default rather than being capped by it:
// an operation that outlives the default but finishes inside the caller's
// deadline succeeds.
func TestWaitOp_CallerDeadlineOverridesTheDefault(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	slow := funcOp{wait: func(ctx context.Context) error {
		select {
		case <-time.After(100 * time.Millisecond):
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}}
	if err := waitOp(ctx, slow, 10*time.Millisecond); err != nil {
		t.Fatalf("caller's deadline should govern, not the default: %v", err)
	}
}

func TestWaitOp_CompletedOperationIsUnchanged(t *testing.T) {
	ok := funcOp{wait: func(context.Context) error { return nil }}
	if err := waitOp(context.Background(), ok, time.Second); err != nil {
		t.Fatalf("want nil, got %v", err)
	}

	realErr := errors.New("Failed creating instance record: already exists")
	fails := funcOp{wait: func(context.Context) error { return realErr }}
	err := waitOp(context.Background(), fails, time.Second)
	if err != realErr {
		t.Fatalf("a finished operation's error must come back as is, got %v", err)
	}
	if errors.Is(err, ErrOperationTimeout) {
		t.Fatal("a real failure must not read as a timeout")
	}
}

// A caller that cancels is not a timeout: the operation did not wedge, the
// caller gave up.
func TestWaitOp_CallerCancelIsNotATimeout(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := within(t, 2*time.Second, func() error { return waitOp(ctx, hangOp{}, time.Hour) })
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
	if errors.Is(err, ErrOperationTimeout) {
		t.Fatal("a cancel must not read as a timeout")
	}
}

func TestWaitOperation_AppliesTheDefault(t *testing.T) {
	shrinkOpTimeouts(t, 30*time.Millisecond)
	err := within(t, 2*time.Second, func() error { return WaitOperation(context.Background(), hangOp{}) })
	assertTimeout(t, err)
}

func TestOperationTimeoutError_Message(t *testing.T) {
	if got := (&OperationTimeoutError{Timeout: time.Minute}).Error(); !strings.Contains(got, "1m0s") {
		t.Errorf("message should name the deadline: %q", got)
	}
	if got := (&OperationTimeoutError{}).Error(); !strings.Contains(got, "caller") {
		t.Errorf("message should say the caller's deadline ran out: %q", got)
	}
}

// shrinkOpTimeouts makes every class of wait deadline d for one test.
func shrinkOpTimeouts(t *testing.T, d time.Duration) {
	t.Helper()
	prev := [3]time.Duration{opTimeout, longOpTimeout, execOpTimeout}
	opTimeout, longOpTimeout, execOpTimeout = d, d, d
	t.Cleanup(func() { opTimeout, longOpTimeout, execOpTimeout = prev[0], prev[1], prev[2] })
}

// wedgedServer answers every operation-starting call with an operation that
// never completes.
type wedgedServer struct{ incusclient.InstanceServer }

func (wedgedServer) GetInstance(name string) (*api.Instance, string, error) {
	return &api.Instance{
		Name: name,
		InstancePut: api.InstancePut{
			Config:  map[string]string{"k": "v", "environment.K": "v", LabelPrefix + "l": "v"},
			Devices: map[string]map[string]string{"eth0": {"type": "nic", "security.acls": "a"}, "data": {"type": "disk", "size": "1GiB"}},
		},
	}, "etag", nil
}

func (wedgedServer) HasExtension(string) bool { return false }
func (wedgedServer) GetImageAlias(string) (*api.ImageAliasesEntry, string, error) {
	return nil, "", api.StatusErrorf(404, "not found")
}
func (wedgedServer) CreateInstance(api.InstancesPost) (incusclient.Operation, error) {
	return hangOp{}, nil
}
func (wedgedServer) UpdateInstance(string, api.InstancePut, string) (incusclient.Operation, error) {
	return hangOp{}, nil
}
func (wedgedServer) UpdateInstanceState(string, api.InstanceStatePut, string) (incusclient.Operation, error) {
	return hangOp{}, nil
}
func (wedgedServer) DeleteInstance(string) (incusclient.Operation, error) { return hangOp{}, nil }
func (wedgedServer) RenameInstance(string, api.InstancePost) (incusclient.Operation, error) {
	return hangOp{}, nil
}
func (wedgedServer) CreateImage(api.ImagesPost, *incusclient.ImageCreateArgs) (incusclient.Operation, error) {
	return hangOp{}, nil
}
func (wedgedServer) CreateInstanceFromBackup(incusclient.InstanceBackupArgs) (incusclient.Operation, error) {
	return hangOp{}, nil
}
func (wedgedServer) CreateInstanceBackup(string, api.InstanceBackupsPost) (incusclient.Operation, error) {
	return hangOp{}, nil
}
func (wedgedServer) ExecInstance(string, api.InstanceExecPost, *incusclient.InstanceExecArgs) (incusclient.Operation, error) {
	return hangOp{}, nil
}

// TestClient_OperationWaitsAreBounded (#3470): every Client method that
// waits on an Incus operation returns the typed timeout error instead of
// blocking forever when the operation never completes. On main each of these
// blocks in op.Wait().
func TestClient_OperationWaitsAreBounded(t *testing.T) {
	shrinkOpTimeouts(t, 30*time.Millisecond)
	c := &Client{server: wedgedServer{}}

	cases := map[string]func() error{
		"CreateContainer":        func() error { return c.CreateContainer(ContainerConfig{Name: "b", Image: "images:debian/12"}) },
		"StartContainer":         func() error { return c.StartContainer("b") },
		"StopContainer":          func() error { return c.StopContainer("b", true) },
		"FreezeContainer":        func() error { return c.FreezeContainer("b") },
		"UnfreezeContainer":      func() error { return c.UnfreezeContainer("b") },
		"DeleteContainer":        func() error { return c.DeleteContainer("b") },
		"Exec":                   func() error { return c.Exec("b", []string{"true"}) },
		"ExecWithOutput":         func() error { _, _, err := c.ExecWithOutput("b", []string{"true"}); return err },
		"ExecWithExitCode":       func() error { _, _, _, err := c.ExecWithExitCode("b", []string{"true"}); return err },
		"UpdateContainerConfig":  func() error { return c.UpdateContainerConfig("b", "k", "v2") },
		"UnsetEnv":               func() error { return c.UnsetEnv("b", "K") },
		"PublishImage":           func() error { _, err := c.PublishImage("b", "alias", nil); return err },
		"SetCPULimit":            func() error { return c.SetCPULimit("b", "2") },
		"SetCPUConfig":           func() error { return c.SetCPUConfig("b", "2", "") },
		"SetConfig":              func() error { return c.SetConfig("b", "k", "v2") },
		"UnsetConfig":            func() error { return c.UnsetConfig("b", "k") },
		"SetDeviceSize":          func() error { return c.SetDeviceSize("b", "data", "2GiB") },
		"SetLabels":              func() error { return c.SetLabels("b", map[string]string{"x": "y"}) },
		"AddLabel":               func() error { return c.AddLabel("b", "x", "y") },
		"RemoveLabel":            func() error { return c.RemoveLabel("b", "l") },
		"DetachACLFromContainer": func() error { return c.DetachACLFromContainer("b", "eth0") },
		"SetDeviceConfig":        func() error { return c.SetDeviceConfig("b", "eth0", map[string]string{"k": "v"}) },
		"RenameInstance":         func() error { return c.RenameInstance("b", "c") },
		"ImportInstance":         func() error { return c.ImportInstance("b", "default", nil, ImportOptions{}) },
		"ExportInstance (stored backup)": func() error {
			r, err := c.ExportInstance("b")
			if r != nil {
				_ = r.Close()
			}
			return err
		},
	}
	for name, call := range cases {
		t.Run(name, func(t *testing.T) {
			assertTimeout(t, within(t, 5*time.Second, call))
		})
	}
}

// TestClient_WaitClasses pins which deadline each class of wait gets: a
// short default, a long one for transfer-sized work, and a longer one for
// exec, whose duration is the command's, not Incus's.
func TestClient_WaitClasses(t *testing.T) {
	c := &Client{server: wedgedServer{}}
	set := func(def, long, exec time.Duration) {
		prev := [3]time.Duration{opTimeout, longOpTimeout, execOpTimeout}
		opTimeout, longOpTimeout, execOpTimeout = def, long, exec
		t.Cleanup(func() { opTimeout, longOpTimeout, execOpTimeout = prev[0], prev[1], prev[2] })
	}
	timeoutOf := func(t *testing.T, call func() error) time.Duration {
		t.Helper()
		var te *OperationTimeoutError
		if err := within(t, 5*time.Second, call); !errors.As(err, &te) {
			t.Fatalf("want *OperationTimeoutError, got %v", err)
		}
		return te.Timeout
	}
	set(10*time.Millisecond, 20*time.Millisecond, 30*time.Millisecond)

	for name, tc := range map[string]struct {
		call func() error
		want time.Duration
	}{
		"StartContainer (default)":  {func() error { return c.StartContainer("b") }, 10 * time.Millisecond},
		"SetConfig (default)":       {func() error { return c.SetConfig("b", "k", "v") }, 10 * time.Millisecond},
		"DeleteContainer (default)": {func() error { return c.DeleteContainer("b") }, 10 * time.Millisecond},
		"RenameInstance (default)":  {func() error { return c.RenameInstance("b", "c") }, 10 * time.Millisecond},
		"CreateContainer (long)": {func() error {
			return c.CreateContainer(ContainerConfig{Name: "b", Image: "images:debian/12"})
		}, 20 * time.Millisecond},
		"PublishImage (long)":   {func() error { _, err := c.PublishImage("b", "a", nil); return err }, 20 * time.Millisecond},
		"ImportInstance (long)": {func() error { return c.ImportInstance("b", "default", nil, ImportOptions{}) }, 20 * time.Millisecond},
		"ExportInstance (long)": {func() error { _, err := c.ExportInstance("b"); return err }, 20 * time.Millisecond},
		"Exec (exec)":           {func() error { return c.Exec("b", []string{"true"}) }, 30 * time.Millisecond},
		"ExecWithOutput (exec)": {func() error { _, _, err := c.ExecWithOutput("b", []string{"true"}); return err }, 30 * time.Millisecond},
		"ExecWithExitCode (exec)": {func() error {
			_, _, _, err := c.ExecWithExitCode("b", []string{"true"})
			return err
		}, 30 * time.Millisecond},
	} {
		t.Run(name, func(t *testing.T) {
			if got := timeoutOf(t, tc.call); got != tc.want {
				t.Errorf("deadline = %s, want %s", got, tc.want)
			}
		})
	}
}

// The named defaults are documented promises; changing one should be a
// deliberate edit to this test too.
func TestOperationTimeoutDefaults(t *testing.T) {
	if DefaultOperationTimeout != 10*time.Minute || LongOperationTimeout != 6*time.Hour || ExecOperationTimeout != 24*time.Hour {
		t.Fatalf("defaults changed: %s / %s / %s", DefaultOperationTimeout, LongOperationTimeout, ExecOperationTimeout)
	}
	if opTimeout != DefaultOperationTimeout || longOpTimeout != LongOperationTimeout || execOpTimeout != ExecOperationTimeout {
		t.Fatal("production deadlines must start at the named defaults")
	}
}

// An operation that fails with a deadline error of its own (an HTTP client
// timeout inside Incus, say) while the wait's deadline has not passed is a
// failure, not this package's timeout.
func TestWaitOp_OperationsOwnDeadlineErrorIsNotOurTimeout(t *testing.T) {
	own := fmt.Errorf("fetch image: %w", context.DeadlineExceeded)
	op := funcOp{wait: func(context.Context) error { return own }}
	if err := waitOp(context.Background(), op, time.Hour); err != own {
		t.Fatalf("want the operation's own error as is, got %v", err)
	}
}

// finishedOp completed successfully with metadata.
type finishedOp struct {
	incusclient.Operation
	meta map[string]any
}

func (finishedOp) Wait() error                       { return nil }
func (finishedOp) WaitContext(context.Context) error { return nil }
func (o finishedOp) Get() api.Operation              { return api.Operation{Metadata: o.meta} }

// cleanupWedgedServer completes the main operation but wedges the
// best-effort cleanup after it.
type cleanupWedgedServer struct{ wedgedServer }

func (cleanupWedgedServer) GetImageAlias(string) (*api.ImageAliasesEntry, string, error) {
	return &api.ImageAliasesEntry{ImageAliasesEntryPut: api.ImageAliasesEntryPut{Target: "old"}}, "", nil
}
func (cleanupWedgedServer) CreateImage(api.ImagesPost, *incusclient.ImageCreateArgs) (incusclient.Operation, error) {
	return finishedOp{meta: map[string]any{"fingerprint": "new"}}, nil
}
func (cleanupWedgedServer) DeleteImageAlias(string) error               { return nil }
func (cleanupWedgedServer) CreateImageAlias(api.ImageAliasesPost) error { return nil }
func (cleanupWedgedServer) DeleteImage(string) (incusclient.Operation, error) {
	return hangOp{}, nil
}
func (cleanupWedgedServer) CreateInstanceBackup(string, api.InstanceBackupsPost) (incusclient.Operation, error) {
	return finishedOp{}, nil
}
func (cleanupWedgedServer) GetInstanceBackupFile(_, _ string, req *incusclient.BackupFileRequest) (*incusclient.BackupFileResponse, error) {
	_, err := req.BackupFile.Write([]byte("tar"))
	return &incusclient.BackupFileResponse{}, err
}
func (cleanupWedgedServer) DeleteInstanceBackup(string, string) (incusclient.Operation, error) {
	return hangOp{}, nil
}

func TestClient_CleanupWaitsAreBounded(t *testing.T) {
	shrinkOpTimeouts(t, 30*time.Millisecond)
	c := &Client{server: cleanupWedgedServer{}}

	t.Run("PublishImage reaping the replaced image", func(t *testing.T) {
		fp, err := within2(t, func() (string, error) { return c.PublishImage("b", "alias", nil) })
		if err != nil || fp != "new" {
			t.Fatalf("a wedged reap is best-effort and must not fail the publish: %q, %v", fp, err)
		}
	})
	t.Run("ExportInstance removing its stored backup", func(t *testing.T) {
		r, err := c.ExportInstance("b")
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, r)
		assertTimeout(t, within(t, 5*time.Second, r.Close))
	})
}

func within2(t *testing.T, f func() (string, error)) (string, error) {
	t.Helper()
	var s string
	err := within(t, 5*time.Second, func() error {
		var err error
		s, err = f()
		return err
	})
	return s, err
}
