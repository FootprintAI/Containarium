package audit

import (
	"context"
	"errors"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	k8stesting "k8s.io/client-go/testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/footprintai/containarium/pkg/core/box/k8s/boxmeta"
)

func boxPod(namespace, name, tenant string, phase corev1.PodPhase) *corev1.Pod {
	labels := map[string]string{boxmeta.ManagedByLabel: boxmeta.ManagedByValue}
	if tenant != "" {
		labels[boxmeta.TenantLabel] = tenant
	}
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace, Labels: labels},
		Status:     corev1.PodStatus{Phase: phase},
	}
}

func TestK8sSource_FindsRunningTenantBoxes(t *testing.T) {
	cs := fake.NewSimpleClientset(
		boxPod("tenant-alice", "alice-abc123", "alice", corev1.PodRunning),
		boxPod("tenant-bob", "bob-def456", "bob", corev1.PodRunning),
	)

	boxes, err := NewK8sSessionSource(cs, "").Boxes(context.Background())
	if err != nil {
		t.Fatalf("boxes: %v", err)
	}
	if len(boxes) != 2 {
		t.Fatalf("found %d boxes, want 2 — a box the collector never lists produces no login "+
			"records, which reads as if nobody logged in", len(boxes))
	}

	byName := map[string]SessionBox{}
	for _, b := range boxes {
		byName[b.Name] = b
	}
	alice, ok := byName["alice"]
	if !ok {
		t.Fatalf("boxes are not keyed by tenant: %+v", boxes)
	}
	if alice.Username != "alice" {
		t.Errorf("username = %q, want the tenant", alice.Username)
	}
	// The pod name must survive to ReadSessions, but must NOT become the
	// audit resource ID: pods are replaced on restart and resize.
	if alice.Ref != "tenant-alice/alice-abc123" {
		t.Errorf("ref = %q, want namespace/pod so the log can be located", alice.Ref)
	}
}

// A pod this platform owns but that is not a tenant's box — the gateway —
// has no tenant to attribute a login to.
func TestK8sSource_SkipsNonTenantPods(t *testing.T) {
	cs := fake.NewSimpleClientset(
		boxPod("containarium", "sshpiper-xyz", "", corev1.PodRunning),
		boxPod("tenant-alice", "alice-abc", "alice", corev1.PodRunning),
	)

	boxes, _ := NewK8sSessionSource(cs, "").Boxes(context.Background())
	if len(boxes) != 1 || boxes[0].Name != "alice" {
		t.Errorf("got %+v, want only the tenant box", boxes)
	}
}

// Reading the log of a pod that is not up yet fails the read and would be
// logged as a collection error on every pass.
func TestK8sSource_SkipsPodsThatAreNotRunning(t *testing.T) {
	cs := fake.NewSimpleClientset(
		boxPod("tenant-alice", "alice-abc", "alice", corev1.PodPending),
		boxPod("tenant-bob", "bob-old", "bob", corev1.PodSucceeded),
	)

	boxes, _ := NewK8sSessionSource(cs, "").Boxes(context.Background())
	if len(boxes) != 0 {
		t.Errorf("got %+v, want none — neither pod can serve a log", boxes)
	}
}

func TestK8sSource_ReadsThePodLog(t *testing.T) {
	cs := fake.NewSimpleClientset(boxPod("tenant-alice", "alice-abc", "alice", corev1.PodRunning))
	src := NewK8sSessionSource(cs, "")

	out, err := src.ReadSessions(context.Background(), SessionBox{
		Name: "alice", Username: "alice", Ref: "tenant-alice/alice-abc",
	})
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if out == "" {
		t.Error("read returned nothing from the pod log")
	}
}

func TestK8sSource_RejectsAMalformedRef(t *testing.T) {
	src := NewK8sSessionSource(fake.NewSimpleClientset(), "")
	for _, ref := range []string{"", "no-slash", "/pod", "ns/"} {
		if _, err := src.ReadSessions(context.Background(), SessionBox{Ref: ref}); err == nil {
			t.Errorf("ref %q was accepted; a bad reference must be an error, not a silent "+
				"empty log that reads as no logins", ref)
		}
	}
}

// The apiserver's stamp is complete; dropbear's has neither a year nor a
// zone. When both are present the apiserver's must win.
func TestK8sSource_PrefersTheApiserverTimestamp(t *testing.T) {
	src := NewK8sSessionSource(fake.NewSimpleClientset(), "")
	podTS := time.Date(2026, time.August, 9, 12, 34, 56, 0, time.UTC)
	line := podTS.Format(time.RFC3339Nano) +
		` Mar 12 14:30:01 Pubkey auth succeeded for 'alice' with ssh-ed25519 key SHA256:abc from 10.0.0.1:54321`

	ts, user, source, method, ok := src.ParseLine(line, 2026, time.Time{})
	if !ok {
		t.Fatal("a stamped pod-log line did not parse")
	}
	if !ts.Equal(podTS) {
		t.Errorf("timestamp = %v, want the apiserver's %v — dropbear's has no year or zone, so "+
			"a record built from it disagrees with every other view of this log", ts, podTS)
	}
	if user != "alice" || source != "10.0.0.1" || method != "publickey" {
		t.Errorf("got user=%q source=%q method=%q", user, source, method)
	}
}

// Timestamps are best-effort per runtime; an unstamped line must still parse.
func TestK8sSource_ParsesAnUnstampedLine(t *testing.T) {
	src := NewK8sSessionSource(fake.NewSimpleClientset(), "")
	line := `Mar 12 14:30:01 Pubkey auth succeeded for 'alice' with ssh-ed25519 key SHA256:abc from 10.0.0.1:54321`

	ts, user, _, _, ok := src.ParseLine(line, 2026, time.Time{})
	if !ok || user != "alice" {
		t.Fatalf("unstamped line did not parse: ok=%v user=%q", ok, user)
	}
	if ts.Day() != 12 || ts.Month() != time.March {
		t.Errorf("timestamp = %v, want dropbear's own when the apiserver supplied none", ts)
	}
}

func TestK8sSource_NonLoginLinesAreIgnored(t *testing.T) {
	src := NewK8sSessionSource(fake.NewSimpleClientset(), "")
	stamp := time.Now().UTC().Format(time.RFC3339Nano)
	for _, line := range []string{
		stamp + " Child connection from 10.0.0.1:54321",
		stamp + " Exit before auth: Disconnect received",
		stamp + " Not a log line at all",
	} {
		if _, _, _, _, ok := src.ParseLine(line, 2026, time.Time{}); ok {
			t.Errorf("recorded a login for a line that is not one:\n%s", line)
		}
	}
}

// The read window is an efficiency bound. A box read for the first time gets
// the lookback; afterwards each read reaches back past the previous one, so a
// modest clock skew between the node and this process cannot drop a login.
func TestK8sSource_ReadWindowOverlapsThePreviousRead(t *testing.T) {
	src := NewK8sSessionSource(fake.NewSimpleClientset(), "").(*k8sSessionSource)

	first := src.sinceFor("ns/pod")
	if age := time.Since(first); age < k8sLogLookback-time.Minute || age > k8sLogLookback+time.Minute {
		t.Errorf("first read window is %v back, want ~%v — an unbounded first read pulls a "+
			"box's whole retained log, and a short one loses what predates it", age, k8sLogLookback)
	}

	readAt := time.Now()
	src.markRead("ns/pod", readAt)
	next := src.sinceFor("ns/pod")
	if !next.Before(readAt) {
		t.Errorf("next window starts at %v, not before the last read at %v — with no overlap, "+
			"clock skew between the node and this process silently drops logins", next, readAt)
	}
	if readAt.Sub(next) != k8sLogOverlap {
		t.Errorf("overlap = %v, want %v", readAt.Sub(next), k8sLogOverlap)
	}
}

// A failed read must leave the window open, or the logins it could not fetch
// are skipped by the read that follows.
func TestK8sSource_FailedReadDoesNotAdvanceTheWindow(t *testing.T) {
	src := NewK8sSessionSource(fake.NewSimpleClientset(), "").(*k8sSessionSource)

	// The window checked has to be the one the failing read touched, or the
	// test passes no matter where the window is advanced.
	const ref = "malformed"

	before := src.sinceFor(ref)
	// A malformed ref fails before any apiserver call — the earliest failure
	// there is, and the one most likely to be mishandled.
	if _, err := src.ReadSessions(context.Background(), SessionBox{Ref: ref}); err == nil {
		t.Fatal("expected the malformed ref to fail")
	}
	after := src.sinceFor(ref)

	if after.Sub(before) > time.Second {
		t.Errorf("the window moved from %v to %v despite the read failing — the logins that "+
			"read missed would never be collected", before, after)
	}
}

// The window map is keyed by pod, and a pod is replaced on every restart and
// resize. Without pruning it gains an entry per box lifetime and never loses
// one, in a process meant to run for months.
func TestK8sSource_ForgetsWindowsOfPodsThatAreGone(t *testing.T) {
	cs := fake.NewSimpleClientset(boxPod("tenant-alice", "alice-new", "alice", corev1.PodRunning))
	src := NewK8sSessionSource(cs, "").(*k8sSessionSource)

	// A window left behind by a pod that has since been replaced.
	src.markRead("tenant-alice/alice-old", time.Now())
	src.markRead("tenant-alice/alice-new", time.Now())

	if _, err := src.Boxes(context.Background()); err != nil {
		t.Fatalf("boxes: %v", err)
	}

	src.mu.Lock()
	defer src.mu.Unlock()
	if _, stale := src.lastRead["tenant-alice/alice-old"]; stale {
		t.Error("kept the window of a pod that no longer exists — one entry per box lifetime, " +
			"never released, in a daemon that runs for months")
	}
	if _, live := src.lastRead["tenant-alice/alice-new"]; !live {
		t.Error("dropped the window of a pod that still exists — the next read would pull the " +
			"full lookback again for every box on every pass")
	}
}

// A failed listing must not prune: resetting every window to the initial
// lookback makes the next pass re-read a day of logs for the whole fleet.
func TestK8sSource_KeepsWindowsWhenListingFails(t *testing.T) {
	cs := fake.NewSimpleClientset()
	cs.PrependReactor("list", "pods", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("apiserver down")
	})
	src := NewK8sSessionSource(cs, "").(*k8sSessionSource)
	src.markRead("tenant-alice/alice-abc", time.Now())

	if _, err := src.Boxes(context.Background()); err == nil {
		t.Fatal("expected the listing to fail")
	}

	src.mu.Lock()
	defer src.mu.Unlock()
	if _, ok := src.lastRead["tenant-alice/alice-abc"]; !ok {
		t.Error("a failed listing dropped every read window — the next pass would re-read the " +
			"full lookback for the whole fleet")
	}
}
