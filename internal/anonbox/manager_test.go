package anonbox

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/lxc/incus/v7/shared/api"
	"golang.org/x/crypto/ssh"

	"github.com/footprintai/containarium/pkg/core/box"
	"github.com/footprintai/containarium/pkg/core/incus"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// --- fakes -----------------------------------------------------------------

type writtenFile struct {
	path, mode string
	content    string
}

// fakeBoxes records every call Ensure makes against the box backend and
// serves List from an in-memory table so reuse/expiry paths are testable
// without Incus.
type fakeBoxes struct {
	boxes     []box.BoxStatus
	createErr error

	created   []box.BoxSpec
	deleted   []box.BoxRef
	ttls      map[string]time.Time
	files     map[string][]writtenFile
	execs     [][]string
	execErr   error               // returned by every Exec when set (#2202)
	catOutput map[string]string   // stdout for `cat <path>` execs (#2206); missing path = error
	owners    map[string]string   // SetOwner, by box name
	keys      map[string][]string // SetAuthorizedKeys, by box name
	writes    []box.BoxRef        // every ref a claim-path write was addressed to
}

func newFakeBoxes() *fakeBoxes {
	return &fakeBoxes{ttls: map[string]time.Time{}, files: map[string][]writtenFile{}, owners: map[string]string{}, keys: map[string][]string{}}
}

func (f *fakeBoxes) Create(_ context.Context, spec box.BoxSpec) (*box.BoxStatus, error) {
	if f.createErr != nil {
		return nil, f.createErr
	}
	f.created = append(f.created, spec)
	st := box.BoxStatus{
		Ref:       box.BoxRef{Tenant: spec.Ref.Tenant, Name: spec.Ref.Tenant + "-container"},
		State:     pb.ContainerState_CONTAINER_STATE_RUNNING,
		IPAddress: "10.100.0.57",
		Labels:    spec.Labels,
		Isolation: spec.Isolation,
	}
	f.boxes = append(f.boxes, st)
	return &st, nil
}

func (f *fakeBoxes) Delete(_ context.Context, ref box.BoxRef, _ bool) error {
	f.deleted = append(f.deleted, ref)
	kept := f.boxes[:0]
	for _, b := range f.boxes {
		if b.Ref.Name != ref.Name {
			kept = append(kept, b)
		}
	}
	f.boxes = kept
	return nil
}

func (f *fakeBoxes) List(_ context.Context) ([]box.BoxStatus, error) {
	out := make([]box.BoxStatus, len(f.boxes))
	copy(out, f.boxes)
	for i := range out {
		if exp, ok := f.ttls[out[i].Ref.Name]; ok {
			out[i].TTLExpiresAt = exp
		} else {
			out[i].TTLExpiresAt = time.Time{}
		}
		if owner, ok := f.owners[out[i].Ref.Name]; ok {
			out[i].Ref.Tenant = owner
		}
	}
	return out, nil
}

func (f *fakeBoxes) SetTTL(_ context.Context, ref box.BoxRef, at *time.Time) error {
	if at == nil {
		delete(f.ttls, ref.Name)
		return nil
	}
	f.ttls[ref.Name] = *at
	return nil
}

func (f *fakeBoxes) Exec(_ context.Context, _ box.BoxRef, cmd []string) (string, string, error) {
	f.execs = append(f.execs, cmd)
	if f.execErr != nil {
		return "", "agent unavailable", f.execErr
	}
	if len(cmd) == 2 && cmd[0] == "cat" {
		if out, ok := f.catOutput[cmd[1]]; ok {
			return out, "", nil
		}
		return "", "No such file or directory", errors.New("exit 1")
	}
	return "", "", nil
}

func (f *fakeBoxes) WriteFile(_ context.Context, ref box.BoxRef, path string, content []byte, mode string) error {
	f.files[ref.Name] = append(f.files[ref.Name], writtenFile{path: path, mode: mode, content: string(content)})
	return nil
}

// fakeACLs is the Incus ACL/NIC slice.
type fakeACLs struct {
	acls      map[string]incus.ACLConfig
	nics      map[string]incus.NICDevice
	devKeys   map[string]map[string]string
	createErr error
}

func newFakeACLs() *fakeACLs {
	return &fakeACLs{acls: map[string]incus.ACLConfig{}, nics: map[string]incus.NICDevice{}, devKeys: map[string]map[string]string{}}
}

func (f *fakeACLs) GetNetworkACL(name string) (*api.NetworkACL, error) {
	if _, ok := f.acls[name]; !ok {
		return nil, errors.New("not found")
	}
	acl := &api.NetworkACL{}
	acl.Name = name
	return acl, nil
}
func (f *fakeACLs) CreateNetworkACL(c incus.ACLConfig) error {
	if f.createErr != nil {
		return f.createErr
	}
	f.acls[c.Name] = c
	return nil
}
func (f *fakeACLs) UpdateNetworkACL(name string, c incus.ACLConfig) error {
	f.acls[name] = c
	return nil
}
func (f *fakeACLs) EnsureNICDevice(name string, want incus.NICDevice) error {
	f.nics[name] = want
	return nil
}
func (f *fakeACLs) SetDeviceConfig(name, dev string, keys map[string]string) error {
	f.devKeys[name+"/"+dev] = keys
	return nil
}

// --- helpers ---------------------------------------------------------------

func testKey(t *testing.T) (authorizedKey, fingerprint string) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub))), ssh.FingerprintSHA256(sshPub)
}

type harness struct {
	m     *Manager
	boxes *fakeBoxes
	acls  *fakeACLs
	now   time.Time
}

func newHarness(t *testing.T, mut func(*Config)) *harness {
	t.Helper()
	h := &harness{boxes: newFakeBoxes(), acls: newFakeACLs(), now: time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)}
	cfg := Config{
		Limits:        DefaultLimits(),
		NICDevice:     "eth0",
		Bridge:        "containarium0",
		ClaimSecret:   func(box string) string { return "secret-for-" + box },
		ClaimURLBase:  "https://cloud.example.test/claim",
		DoorStatePath: "", // in-memory door state
		Now:           func() time.Time { return h.now },
	}
	if mut != nil {
		mut(&cfg)
	}
	h.m = New(h.boxes, h.acls, cfg)
	return h
}

func fileNamed(t *testing.T, files []writtenFile, path string) writtenFile {
	t.Helper()
	// Last match: a box recreated under the same name appends a second
	// banner, and the newest is the one the user will see.
	var found *writtenFile
	for i := range files {
		if files[i].path == path {
			found = &files[i]
		}
	}
	if found == nil {
		t.Fatalf("file %s not written (have %+v)", path, files)
	}
	return *found
}

// --- tests -----------------------------------------------------------------

func TestEnsure_NewFingerprint_CreatesVM(t *testing.T) {
	h := newHarness(t, nil)
	key, fp := testKey(t)

	res, err := h.m.Ensure(context.Background(), EnsureRequest{Fingerprint: fp, PublicKey: key, SourceIP: "198.51.100.7"})
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}

	if len(h.boxes.created) != 1 {
		t.Fatalf("created %d boxes, want 1", len(h.boxes.created))
	}
	spec := h.boxes.created[0]
	if spec.Isolation != pb.IsolationType_ISOLATION_TYPE_VM {
		t.Errorf("Isolation = %v, want VM", spec.Isolation)
	}
	if spec.OSType != pb.OSType_OS_TYPE_UBUNTU_2404 {
		t.Errorf("OSType = %v, want Ubuntu 24.04", spec.OSType)
	}
	if spec.Resources != (box.ResourceLimits{CPU: "2", Memory: "4GB", Disk: "20GB"}) {
		t.Errorf("Resources = %+v, want the default limits", spec.Resources)
	}
	if len(spec.SSHKeys) != 1 || spec.SSHKeys[0] != key {
		t.Errorf("SSHKeys = %v, want exactly the caller's key", spec.SSHKeys)
	}
	if spec.EnablePodman || spec.EnablePodmanPrivileged {
		t.Errorf("podman must be off for an anonymous VM")
	}
	if !strings.HasPrefix(spec.Ref.Tenant, "anon-") || len(spec.Ref.Tenant) != len("anon-")+8 {
		t.Errorf("tenant = %q, want anon-<8 hex>", spec.Ref.Tenant)
	}
	for _, k := range []string{LabelFingerprint, LabelFPHash, LabelCreatedAt, LabelSourceIP, LabelClaimTokenID} {
		if spec.Labels[k] == "" {
			t.Errorf("label %s missing", k)
		}
	}
	if spec.Labels[LabelFingerprint] != fp {
		t.Errorf("label %s = %q, want %q", LabelFingerprint, spec.Labels[LabelFingerprint], fp)
	}
	if spec.Labels[LabelSourceIP] != "198.51.100.7" {
		t.Errorf("label %s = %q", LabelSourceIP, spec.Labels[LabelSourceIP])
	}

	// TTL stamped at birth.
	wantExp := h.now.Add(DefaultLimits().TTL)
	if got := h.boxes.ttls[res.BoxName]; !got.Equal(wantExp) {
		t.Errorf("TTL = %v, want %v", got, wantExp)
	}

	// Egress ACL: default drop on the NIC, four allows.
	acl, ok := h.acls.acls[EgressACLName]
	if !ok {
		t.Fatalf("ACL %s not created", EgressACLName)
	}
	if len(acl.EgressRules) != 4 || len(acl.IngressRules) != 0 {
		t.Errorf("ACL rules egress=%d ingress=%d, want 4/0: %+v", len(acl.EgressRules), len(acl.IngressRules), acl)
	}
	if nic := h.acls.nics[res.BoxName]; nic.Name != "eth0" || nic.Network != "containarium0" {
		t.Errorf("NIC = %+v, want eth0 on containarium0", nic)
	}
	keys := h.acls.devKeys[res.BoxName+"/eth0"]
	if keys["security.acls"] != EgressACLName || keys["security.acls.default.egress.action"] != "drop" {
		t.Errorf("NIC acl keys = %v", keys)
	}

	// In-guest files.
	files := h.boxes.files[res.BoxName]
	banner := fileNamed(t, files, BannerPath)
	if !strings.Contains(banner.content, "containarium claim") || !strings.Contains(banner.content, "preempt") {
		t.Errorf("banner missing claim hint or preemptible warning:\n%s", banner.content)
	}
	if strings.Contains(banner.content, "previous box expired") {
		t.Errorf("first-ever box must not say the previous one expired")
	}
	claim := fileNamed(t, files, ClaimURLPath)
	if !strings.HasPrefix(claim.content, "https://cloud.example.test/claim?token=v1."+res.BoxName+".") || !strings.Contains(claim.content, "."+spec.Labels[LabelClaimTokenID]+".") {
		t.Errorf("claim-url = %q, want the ClaimURL hook's output carrying the token id", claim.content)
	}

	// Result.
	if res.Reused || res.PreviousExpired {
		t.Errorf("reused=%v previousExpired=%v on a first create", res.Reused, res.PreviousExpired)
	}
	if res.SSHHost != "10.100.0.57" || res.SSHPort != 22 || res.SSHUser != spec.Ref.Tenant {
		t.Errorf("endpoint = %s:%d user %s", res.SSHHost, res.SSHPort, res.SSHUser)
	}
	if !res.TTLExpiresAt.Equal(wantExp) {
		t.Errorf("TTLExpiresAt = %v, want %v", res.TTLExpiresAt, wantExp)
	}
	if len(h.boxes.deleted) != 0 {
		t.Errorf("nothing should be deleted on success, got %v", h.boxes.deleted)
	}
}

func TestEnsure_ExistingLiveBox_Reuses(t *testing.T) {
	h := newHarness(t, nil)
	key, fp := testKey(t)
	req := EnsureRequest{Fingerprint: fp, PublicKey: key}

	first, err := h.m.Ensure(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	h.now = h.now.Add(30 * time.Minute)
	second, err := h.m.Ensure(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}

	if len(h.boxes.created) != 1 {
		t.Fatalf("created %d boxes, want 1 (reconnect must not create)", len(h.boxes.created))
	}
	if !second.Reused || second.BoxName != first.BoxName || second.SSHHost != first.SSHHost {
		t.Errorf("second = %+v, want reuse of %+v", second, first)
	}
	if !second.TTLExpiresAt.Equal(first.TTLExpiresAt) {
		t.Errorf("reconnect must not extend the TTL: %v vs %v", second.TTLExpiresAt, first.TTLExpiresAt)
	}
}

func TestEnsure_ExpiredPrevious_SetsPreviousExpired(t *testing.T) {
	h := newHarness(t, nil)
	key, fp := testKey(t)
	req := EnsureRequest{Fingerprint: fp, PublicKey: key}

	first, err := h.m.Ensure(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	// The sweeper reaped it.
	h.boxes.boxes = nil
	h.now = h.now.Add(5 * time.Hour)

	second, err := h.m.Ensure(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if !second.PreviousExpired || second.Reused {
		t.Errorf("second = %+v, want previousExpired=true reused=false", second)
	}
	if len(h.boxes.created) != 2 {
		t.Errorf("created %d, want a fresh box", len(h.boxes.created))
	}
	banner := fileNamed(t, h.boxes.files[second.BoxName], BannerPath)
	if !strings.Contains(banner.content, "previous box expired") {
		t.Errorf("banner must say the previous box expired:\n%s", banner.content)
	}
	if second.BoxName != first.BoxName {
		t.Errorf("same key must map to the same name: %s vs %s", second.BoxName, first.BoxName)
	}
}

func TestEnsure_CreateFails_NothingToDelete(t *testing.T) {
	h := newHarness(t, nil)
	h.boxes.createErr = errors.New("incus: no kvm")
	key, fp := testKey(t)

	_, err := h.m.Ensure(context.Background(), EnsureRequest{Fingerprint: fp, PublicKey: key})
	if err == nil || !strings.Contains(err.Error(), "no kvm") {
		t.Fatalf("err = %v, want the create error surfaced", err)
	}
	if len(h.boxes.deleted) != 0 {
		t.Errorf("nothing was created, nothing to delete: %v", h.boxes.deleted)
	}
}

func TestEnsure_ACLFails_DeletesPartialBox(t *testing.T) {
	h := newHarness(t, nil)
	h.acls.createErr = errors.New("acl: firewall driver is not nftables")
	key, fp := testKey(t)

	_, err := h.m.Ensure(context.Background(), EnsureRequest{Fingerprint: fp, PublicKey: key})
	if err == nil {
		t.Fatal("want error when the egress guard cannot be applied")
	}
	if len(h.boxes.deleted) != 1 {
		t.Fatalf("partial box must be deleted, deleted=%v", h.boxes.deleted)
	}
	if len(h.boxes.boxes) != 0 {
		t.Errorf("box still listed after cleanup")
	}
}

func TestEnsure_FingerprintMismatch_Rejected(t *testing.T) {
	h := newHarness(t, nil)
	key, _ := testKey(t)
	_, otherFP := testKey(t)

	_, err := h.m.Ensure(context.Background(), EnsureRequest{Fingerprint: otherFP, PublicKey: key})
	if err == nil {
		t.Fatal("want error when the fingerprint does not match the key")
	}
	if len(h.boxes.created) != 0 {
		t.Errorf("nothing may be created on a mismatch")
	}
}

func TestEnsure_BadKey_Rejected(t *testing.T) {
	h := newHarness(t, nil)
	for _, key := range []string{"", "not a key", "ssh-ed25519 AAAA"} {
		if _, err := h.m.Ensure(context.Background(), EnsureRequest{PublicKey: key}); err == nil {
			t.Errorf("key %q: want error", key)
		}
	}
}

func TestEnsure_NoClaimURLHook_SkipsFile(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.ClaimSecret = nil })
	key, fp := testKey(t)

	res, err := h.m.Ensure(context.Background(), EnsureRequest{Fingerprint: fp, PublicKey: key})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range h.boxes.files[res.BoxName] {
		if f.path == ClaimURLPath {
			t.Errorf("claim-url must not be written without a minter")
		}
	}
	fileNamed(t, h.boxes.files[res.BoxName], BannerPath)
}

func TestUsernameFor(t *testing.T) {
	_, fp := testKey(t)
	a, b := UsernameFor(fp), UsernameFor(fp)
	if a != b {
		t.Errorf("not stable: %s vs %s", a, b)
	}
	if !strings.HasPrefix(a, "anon-") || len(a) != 13 {
		t.Errorf("username = %q, want anon-<8 hex>", a)
	}
	for _, r := range a[5:] {
		if !strings.ContainsRune("0123456789abcdef", r) {
			t.Errorf("non-hex rune %q in %s", r, a)
		}
	}
}

func TestEgressACL_Rules(t *testing.T) {
	acl := egressACL()
	if acl.Name != EgressACLName {
		t.Errorf("name = %s", acl.Name)
	}
	want := map[string]bool{"udp/53": false, "tcp/53": false, "tcp/80": false, "tcp/443": false}
	for _, r := range acl.EgressRules {
		k := r.Protocol + "/" + r.DestinationPort
		if _, ok := want[k]; !ok {
			t.Errorf("unexpected rule %+v", r)
		}
		if r.Action != "allow" {
			t.Errorf("rule %s action = %s", k, r.Action)
		}
		want[k] = true
	}
	for k, seen := range want {
		if !seen {
			t.Errorf("rule %s missing", k)
		}
	}
}

func TestEnsure_CallerFaults_AreInvalidRequestErrors(t *testing.T) {
	h := newHarness(t, nil)
	key, _ := testKey(t)
	_, otherFP := testKey(t)
	for name, req := range map[string]EnsureRequest{
		"bad key":  {PublicKey: "nope"},
		"mismatch": {PublicKey: key, Fingerprint: otherFP},
	} {
		_, err := h.m.Ensure(context.Background(), req)
		var inv InvalidRequestError
		if !errors.As(err, &inv) {
			t.Errorf("%s: err %v is not an InvalidRequestError", name, err)
		}
	}
}

func (f *fakeBoxes) SetMeta(_ context.Context, ref box.BoxRef, meta map[string]string) error {
	f.writes = append(f.writes, ref)
	for i := range f.boxes {
		if f.boxes[i].Ref.Name == ref.Name {
			for k, v := range meta {
				f.boxes[i].Labels[k] = v
			}
			return nil
		}
	}
	return errors.New("not found")
}

func (f *fakeBoxes) SetAuthorizedKeys(_ context.Context, ref box.BoxRef, keys []string) error {
	f.writes = append(f.writes, ref)
	f.keys[ref.Name] = append([]string{}, keys...)
	return nil
}

func (f *fakeBoxes) SetOwner(_ context.Context, ref box.BoxRef, tenant string) error {
	f.writes = append(f.writes, ref)
	f.owners[ref.Name] = tenant
	return nil
}
