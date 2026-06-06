package volume

import (
	"fmt"
	"strings"
	"testing"
)

// fakeRunner records calls and returns scripted output keyed by the first
// few args.
type fakeRunner struct {
	calls   [][]string
	storage string // output for `storage list`
	volList string // output for `storage volume list`
	err     error
}

func (f *fakeRunner) Run(args ...string) (string, error) {
	f.calls = append(f.calls, args)
	if f.err != nil {
		return "", f.err
	}
	joined := strings.Join(args, " ")
	switch {
	case strings.HasPrefix(joined, "storage list"):
		return f.storage, nil
	case strings.HasPrefix(joined, "storage volume list"):
		return f.volList, nil
	}
	return "", nil
}

func (f *fakeRunner) lastCall() []string {
	if len(f.calls) == 0 {
		return nil
	}
	return f.calls[len(f.calls)-1]
}

const cephfsCSV = "default,zfs,,3,\nshared,cephfs,,1,\nother,dir,,0,\n"

func TestParseCephfsPools(t *testing.T) {
	got := parseCephfsPools(cephfsCSV)
	if len(got) != 1 || got[0] != "shared" {
		t.Fatalf("parseCephfsPools = %v, want [shared]", got)
	}
	if p := parseCephfsPools("default,zfs,,0,\n"); len(p) != 0 {
		t.Errorf("zfs-only host should report no cephfs pools, got %v", p)
	}
}

func TestSharedVolumesSupported(t *testing.T) {
	m := NewManager(&fakeRunner{storage: cephfsCSV})
	pool, ok, detail := m.SharedVolumesSupported()
	if !ok || pool != "shared" {
		t.Fatalf("expected supported on cephfs host, got ok=%v pool=%q", ok, pool)
	}
	if !strings.Contains(detail, "shared") {
		t.Errorf("detail %q should name the pool", detail)
	}

	m2 := NewManager(&fakeRunner{storage: "default,zfs,,0,\n"})
	if _, ok, _ := m2.SharedVolumesSupported(); ok {
		t.Error("zfs-only host should not support shared volumes")
	}
}

func TestCreate_RejectsWhenUnsupported(t *testing.T) {
	m := NewManager(&fakeRunner{storage: "default,zfs,,0,\n"})
	if _, err := m.Create("data", 1<<30, ""); err == nil {
		t.Fatal("create should be rejected on a non-cephfs host")
	}
}

func TestCreate_ValidatesSize(t *testing.T) {
	m := NewManager(&fakeRunner{storage: cephfsCSV})
	if _, err := m.Create("data", 0, ""); err == nil {
		t.Error("size 0 should be rejected")
	}
	if _, err := m.Create("", 1<<30, ""); err == nil {
		t.Error("empty name should be rejected")
	}
}

func TestCreate_BuildsCommandAndResolvesPool(t *testing.T) {
	f := &fakeRunner{storage: cephfsCSV}
	m := NewManager(f)
	v, err := m.Create("dataset", 2<<30, "") // empty pool → detected "shared"
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if v.Pool != "shared" || v.ContentType != ContentTypeFilesystem {
		t.Errorf("unexpected volume: %+v", v)
	}
	want := []string{"storage", "volume", "create", "shared", "dataset", fmt.Sprintf("size=%d", int64(2<<30))}
	if got := f.lastCall(); strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("create argv = %v, want %v", got, want)
	}
}

func TestAttachArgs_RWAndRO(t *testing.T) {
	rw := attachArgs("alice-container", DeviceName("ds"), "shared", "ds", "/mnt/shared", false)
	wantRW := "config device add alice-container vol-ds disk pool=shared source=ds path=/mnt/shared"
	if strings.Join(rw, " ") != wantRW {
		t.Errorf("rw attach = %q, want %q", strings.Join(rw, " "), wantRW)
	}
	ro := attachArgs("alice-container", DeviceName("ds"), "shared", "ds", "/mnt/shared", true)
	if !strings.HasSuffix(strings.Join(ro, " "), "readonly=true") {
		t.Errorf("ro attach should end with readonly=true: %q", strings.Join(ro, " "))
	}
}

func TestAttach_Validation(t *testing.T) {
	m := NewManager(&fakeRunner{storage: cephfsCSV})
	if err := m.Attach("", "shared", "alice", "/mnt", false); err == nil {
		t.Error("empty volume should be rejected")
	}
	if err := m.Attach("ds", "shared", "alice", "", false); err == nil {
		t.Error("empty mount_path should be rejected")
	}
}

func TestDetach_UsesDeterministicDevice(t *testing.T) {
	f := &fakeRunner{storage: cephfsCSV}
	m := NewManager(f)
	if err := m.Detach("ds", "alice-container"); err != nil {
		t.Fatalf("Detach: %v", err)
	}
	want := "config device remove alice-container vol-ds"
	if got := strings.Join(f.lastCall(), " "); got != want {
		t.Errorf("detach argv = %q, want %q", got, want)
	}
}

func TestList_ParsesCustomVolumes(t *testing.T) {
	f := &fakeRunner{
		storage: cephfsCSV,
		volList: "container,alice,,filesystem,1\ncustom,dataset,,filesystem,2\ncustom,cache,,filesystem,0\n",
	}
	m := NewManager(f)
	vols, err := m.List("shared")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(vols) != 2 {
		t.Fatalf("expected 2 custom volumes, got %d (%+v)", len(vols), vols)
	}
	if vols[0].Name != "dataset" || vols[0].Pool != "shared" {
		t.Errorf("unexpected first volume: %+v", vols[0])
	}
}
