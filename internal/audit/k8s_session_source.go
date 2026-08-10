package audit

import (
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/footprintai/containarium/pkg/core/box/k8s/boxmeta"
)

// The K8s session source (#1189).
//
// A K8s box has no /var/log/auth.log to grep: it runs dropbear as PID 1's
// child with logging to stderr, which the kubelet captures. So the session
// record lives in the pod log, and reading it is an apiserver call rather
// than an exec.
//
// This is why the collector needed a source seam at all. The LXC path
// (exec + grep + sshd patterns) and this one (pod log + dropbear patterns)
// share no step; what they share is everything the collector does with the
// result.

// k8sLogLookback bounds the first read of a box the collector has not seen
// before — on startup, or when a box first appears.
//
// Not unbounded: a box that has been up for months would have the collector
// pull its entire retained log on the first pass, and every record in it is
// one the previous run already wrote. Not short either, because anything
// older than the window on that first pass is lost rather than late. A day
// covers a daemon restart and any plausible collection gap.
const k8sLogLookback = 24 * time.Hour

// k8sSessionSource reads dropbear's output from box pod logs.
type k8sSessionSource struct {
	clientset kubernetes.Interface
	// namespace scopes the pod listing; empty means every namespace, which
	// is the normal case since boxes get a namespace per tenant.
	namespace string

	// mu guards lastRead, which is consulted from the collector's goroutine
	// only today but is cheap to make safe.
	mu sync.Mutex
	// lastRead is the point each box's log was last read up to, used as the
	// apiserver's SinceTime so a poll transfers a poll's worth of log rather
	// than the whole retained history.
	//
	// This is an efficiency bound, NOT de-duplication: the window is
	// deliberately re-read with an overlap and the collector's high-water
	// mark drops what it has already recorded. Using it to skip lines would
	// mean a clock skew between the node and the daemon silently losing
	// logins.
	lastRead map[string]time.Time
}

// NewK8sSessionSource returns the pod-log session source.
//
// namespace scopes the search; pass "" to cover every namespace.
func NewK8sSessionSource(clientset kubernetes.Interface, namespace string) SessionSource {
	return &k8sSessionSource{
		clientset: clientset,
		namespace: namespace,
		lastRead:  make(map[string]time.Time),
	}
}

func (s *k8sSessionSource) Boxes(ctx context.Context) ([]SessionBox, error) {
	pods, err := s.clientset.CoreV1().Pods(s.namespace).List(ctx, metav1.ListOptions{
		LabelSelector: boxmeta.ManagedByLabel + "=" + boxmeta.ManagedByValue,
	})
	if err != nil {
		return nil, fmt.Errorf("list box pods: %w", err)
	}

	var boxes []SessionBox
	for i := range pods.Items {
		pod := &pods.Items[i]
		tenant := pod.Labels[boxmeta.TenantLabel]
		if tenant == "" {
			// Managed by this platform but not a tenant box — the gateway,
			// for instance. Nobody logs into those as a tenant.
			continue
		}
		if pod.Status.Phase != corev1.PodRunning {
			continue
		}
		boxes = append(boxes, SessionBox{
			// The tenant, not the pod name: pods are replaced on restart and
			// resize, and an audit trail whose resource ID changes underneath
			// it cannot be queried for "who logged into this box".
			Name:     tenant,
			Username: tenant,
			Ref:      pod.Namespace + "/" + pod.Name,
		})
	}

	// Drop windows for pods that no longer exist. The key is the pod, and a
	// pod is replaced on every restart and resize — so without this the map
	// gains an entry per box lifetime and never loses one, in a process meant
	// to run for months.
	//
	// Only on a successful list: pruning on a transient empty result would
	// reset every window to the initial lookback, making the next pass re-read
	// a day of logs for the whole fleet.
	s.retainWindows(boxes)

	return boxes, nil
}

// retainWindows forgets the read window of every box not in the current list.
func (s *k8sSessionSource) retainWindows(boxes []SessionBox) {
	live := make(map[string]struct{}, len(boxes))
	for _, b := range boxes {
		live[b.Ref] = struct{}{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for ref := range s.lastRead {
		if _, ok := live[ref]; !ok {
			delete(s.lastRead, ref)
		}
	}
}

func (s *k8sSessionSource) ReadSessions(ctx context.Context, box SessionBox) (string, error) {
	namespace, podName, err := splitPodRef(box.Ref)
	if err != nil {
		return "", err
	}

	opts := &corev1.PodLogOptions{
		Container: boxmeta.BoxContainerName,
		// Ask the apiserver to stamp each line. dropbear's own timestamp is
		// absent under some runtimes, and a login recorded with the wrong
		// time is worse than one recorded with the reader's.
		Timestamps: true,
	}
	if since := s.sinceFor(box.Ref); !since.IsZero() {
		sinceTime := metav1.NewTime(since)
		opts.SinceTime = &sinceTime
	}

	stream, err := s.clientset.CoreV1().Pods(namespace).
		GetLogs(podName, opts).Stream(ctx)
	if err != nil {
		return "", fmt.Errorf("read pod log %s: %w", box.Ref, err)
	}
	defer func() { _ = stream.Close() }()

	// readAt is stamped BEFORE the read, not after: anything logged while the
	// read is in flight must fall inside the next window rather than between
	// the two.
	readAt := time.Now()
	data, err := io.ReadAll(stream)
	if err != nil {
		return "", fmt.Errorf("read pod log %s: %w", box.Ref, err)
	}

	// Only advance on success. A failed read must leave the window open, or
	// the logins it failed to fetch are skipped by the next one.
	s.markRead(box.Ref, readAt)
	return string(data), nil
}

// ParseLine reads one pod-log line.
//
// With Timestamps set, the apiserver prefixes each line with an RFC3339
// stamp. That stamp is preferred over dropbear's own even when both are
// present: dropbear's carries neither a year nor a zone, so it has to be
// reassembled from a guessed year, while the kubelet's is complete and is
// what every other view of this pod's log agrees with.
func (s *k8sSessionSource) ParseLine(line string, year int, fallback time.Time) (time.Time, string, string, string, bool) {
	podTS, rest, hasPodTS := splitPodLogTimestamp(line)
	if hasPodTS {
		line, fallback = rest, podTS
	}

	ts, user, source, method, ok := parseDropbearLine(line, year, fallback)
	if !ok {
		return time.Time{}, "", "", "", false
	}
	if hasPodTS {
		ts = podTS
	}
	return ts, user, source, method, true
}

// splitPodLogTimestamp peels the RFC3339 stamp the apiserver prefixes to each
// line when PodLogOptions.Timestamps is set. Returns ok=false for a line
// without one, since the option is best-effort per runtime.
func splitPodLogTimestamp(line string) (ts time.Time, rest string, ok bool) {
	stamp, remainder, found := strings.Cut(line, " ")
	if !found {
		return time.Time{}, line, false
	}
	parsed, err := time.Parse(time.RFC3339Nano, stamp)
	if err != nil {
		return time.Time{}, line, false
	}
	return parsed, remainder, true
}

// sinceFor returns the SinceTime for a box's next read: the last successful
// read, backed off by an overlap, or the initial lookback for a box not seen
// before.
func (s *k8sSessionSource) sinceFor(ref string) time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	last, ok := s.lastRead[ref]
	if !ok {
		return time.Now().Add(-k8sLogLookback)
	}
	// The overlap covers modest clock skew between the node writing the log
	// and this process reading it. Re-reading costs a few duplicate lines the
	// collector discards; reading too late loses a login for good.
	return last.Add(-k8sLogOverlap)
}

// k8sLogOverlap is how far back each read reaches beyond the previous one.
const k8sLogOverlap = 5 * time.Minute

func (s *k8sSessionSource) markRead(ref string, at time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastRead[ref] = at
}

// splitPodRef splits the "namespace/pod" handle Boxes attached to the box.
func splitPodRef(ref string) (namespace, pod string, err error) {
	for i := 0; i < len(ref); i++ {
		if ref[i] == '/' {
			namespace, pod = ref[:i], ref[i+1:]
			if namespace == "" || pod == "" {
				break
			}
			return namespace, pod, nil
		}
	}
	return "", "", fmt.Errorf("malformed pod reference %q, want namespace/pod", ref)
}
