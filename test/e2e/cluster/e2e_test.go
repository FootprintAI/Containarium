//go:build incus && cluster_e2e

package clustere2e

// The gated KVM e2e lane (#1418): the managed-clusters MVP journey run
// against real everything — real Incus VMs, real k3s, real
// cluster-autoscaler, real VPA — on a VM-capable host. Design:
// docs/architecture/managed-k8s-clusters.md, "End-to-end".
//
// Every assertion is against observed cluster or Incus state (the k8s
// API through the tenant kubeconfig, the Incus API, TCP reachability),
// never against the daemon's own SQL or logs. Rows are asserted through
// the product API (`cluster get` NotFound), which is the tenant-visible
// meaning of "no rows".
//
// Driven CLI-first: every platform action goes through the
// `containarium` binary the lane built, exactly as a tenant would run
// it — no agent-only escape hatches (CLAUDE.md).
//
// Steps are strictly sequential; each builds on the previous one, so a
// failed step aborts the rest instead of cascading noise.
//
// Environment contract (set by scripts/cluster-e2e.sh):
//
//	CONTAINARIUM_E2E_CLI            path to the built containarium binary
//	CONTAINARIUM_E2E_SERVER         daemon HTTP address, e.g. 127.0.0.1:8080
//	CONTAINARIUM_JWT_SECRET         daemon's JWT secret; the lane mints its tenant token
//	CONTAINARIUM_E2E_ADVERTISE_HOST host the kubeconfig must point at ("outside" reach)
//	CONTAINARIUM_E2E_SABOTAGE       "" or "join-token" (prove-the-lane-can-fail runs)
//	CONTAINARIUM_REQUIRE_INCUS      "1" in the lane: a missing environment fails, not skips
//
// Timeouts (durations, optional): CONTAINARIUM_E2E_READY_TIMEOUT
// (default 15m; PRD documents create→kubectl under 10 minutes),
// _SCALEUP_TIMEOUT (12m), _VPA_TIMEOUT (15m), _SCALEDOWN_TIMEOUT (30m —
// stock CA scale-down: 10m delay-after-add + 10m unneeded),
// _DELETE_TIMEOUT (10m).

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/testsupport/incusenv"
	clusterpkg "github.com/footprintai/containarium/pkg/core/cluster"
	"github.com/footprintai/containarium/pkg/core/incus"
)

const (
	tenant      = "e2etenant"
	clusterName = "lane"

	// burnImage runs both the pause-style sleepers and the CPU burner.
	// registry.k8s.io is the same registry the pinned CA image comes
	// from, and it is not rate-limited the way docker.io is.
	burnImage = "registry.k8s.io/e2e-test-images/busybox:1.36.1-1"
)

// vmPrefix is the Incus name prefix every VM of the lane cluster
// carries (spec.go's naming scheme).
var vmPrefix = tenant + "-k8s-" + clusterName + "-"

type lane struct {
	t             *testing.T
	cli           string
	server        string
	token         string
	advertiseHost string
	incus         *incus.Client

	cs  *kubernetes.Clientset
	dyn dynamic.Interface

	kubeconfig    []byte
	baselineNodes []string
	baselineVMs   []string
}

func env(t *testing.T, key string) string {
	t.Helper()
	v := os.Getenv(key)
	if v == "" {
		msg := fmt.Sprintf("%s is not set; the cluster e2e needs the lane script's environment", key)
		if incusenv.DispositionFor(os.Getenv(incusenv.RequireEnv)) == incusenv.Fail {
			t.Fatalf("%s (%s is set, so this is a failure and not a skip)", msg, incusenv.RequireEnv)
		}
		t.Skipf("%s (set %s=1 to make this a failure instead)", msg, incusenv.RequireEnv)
	}
	return v
}

func timeoutEnv(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}

func TestManagedClusterJourney(t *testing.T) {
	if testing.Short() {
		t.Skip("gated KVM lane; not a -short test")
	}

	l := &lane{
		t:             t,
		cli:           env(t, "CONTAINARIUM_E2E_CLI"),
		server:        env(t, "CONTAINARIUM_E2E_SERVER"),
		advertiseHost: env(t, "CONTAINARIUM_E2E_ADVERTISE_HOST"),
		incus:         incusenv.Require(t),
	}

	secret := env(t, "CONTAINARIUM_JWT_SECRET")
	tm, err := auth.NewTokenManager(secret, "containarium")
	if err != nil {
		t.Fatalf("token manager: %v", err)
	}
	// The tenant's own least-privilege token — the journey is the
	// tenant's, not an admin's.
	l.token, err = tm.GenerateAccessToken(tenant, []string{"user"}, 4*time.Hour,
		auth.ScopeClustersRead, auth.ScopeClustersWrite)
	if err != nil {
		t.Fatalf("mint tenant token: %v", err)
	}

	sabotage, err := ParseSabotage(os.Getenv("CONTAINARIUM_E2E_SABOTAGE"))
	if err != nil {
		t.Fatalf("%v", err)
	}
	if sabotage == SabotageJoinToken {
		stop := make(chan struct{})
		defer close(stop)
		go l.sabotageJoinTokens(stop)
		t.Log("SABOTAGE ACTIVE: corrupting worker join tokens — this run is expected to go red")
	}

	// Whatever happens, tear the cluster down so a red run does not
	// leak VMs into the next nightly. Errors are logged, not fatal —
	// the script's sweep is the backstop.
	defer func() {
		out, err := l.runCLI("cluster", "delete", clusterName)
		l.t.Logf("teardown delete: %v %s", err, strings.TrimSpace(out))
	}()

	steps := []struct {
		name string
		fn   func() error
	}{
		{"1_create_kubeconfig_from_outside", l.stepCreate},
		{"2_overflow_scales_up_via_new_ready_node", l.stepOverflowScaleUp},
		{"3_big_pod_lands_on_larger_class_node", l.stepLargerClass},
		{"4_vpa_raises_requests_without_restart_loop", l.stepVPA},
		{"5_scale_to_zero_drains_and_deletes_vm", l.stepScaleToZero},
		{"6_delete_leaves_nothing", l.stepDelete},
	}
	for _, s := range steps {
		if !t.Run(s.name, func(t *testing.T) {
			if err := s.fn(); err != nil {
				l.dumpDiagnostics()
				t.Fatal(err)
			}
		}) {
			t.Fatalf("step %s failed; aborting the journey (later steps depend on it)", s.name)
		}
	}
}

// --- CLI ----------------------------------------------------------------

func (l *lane) runCLI(args ...string) (string, error) {
	full := append([]string{"--http", "--server", l.server, "--token", l.token}, args...)
	cmd := exec.Command(l.cli, full...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// --- step 1: create → kubeconfig works from outside ---------------------

func (l *lane) stepCreate() error {
	readyTimeout := timeoutEnv("CONTAINARIUM_E2E_READY_TIMEOUT", 15*time.Minute)

	if out, err := l.runCLI("cluster", "create", clusterName); err != nil {
		return fmt.Errorf("cluster create: %v\n%s", err, out)
	}

	// The kubeconfig RPC is FailedPrecondition until the cluster is
	// READY, then returns the credential: polling it IS the readiness
	// probe, through the same door a tenant uses.
	err := l.waitFor("cluster READY and kubeconfig served", readyTimeout, 10*time.Second, func() (bool, string) {
		out, err := l.runCLI("cluster", "kubeconfig", clusterName)
		if err != nil {
			return false, strings.TrimSpace(out)
		}
		l.kubeconfig = []byte(out)
		return true, "kubeconfig fetched"
	})
	if err != nil {
		return err
	}

	// "From outside": the credential must point at the advertised host
	// (the passthrough route), not at a VM address only the host can
	// reach.
	host, err := KubeconfigServerHost(l.kubeconfig)
	if err != nil {
		return err
	}
	if got, _, splitErr := net.SplitHostPort(host); splitErr != nil || got != l.advertiseHost {
		return fmt.Errorf("kubeconfig points at %q, want the advertised host %q — that is not reachable from outside", host, l.advertiseHost)
	}

	restCfg, err := clientcmd.RESTConfigFromKubeConfig(l.kubeconfig)
	if err != nil {
		return fmt.Errorf("kubeconfig rest config: %w", err)
	}
	if l.cs, err = kubernetes.NewForConfig(restCfg); err != nil {
		return fmt.Errorf("clientset: %w", err)
	}
	if l.dyn, err = dynamic.NewForConfig(restCfg); err != nil {
		return fmt.Errorf("dynamic client: %w", err)
	}

	// The small group's min worker must register and go Ready — a
	// kubeconfig against an empty cluster is not a working cluster.
	err = l.waitFor("min worker Ready via kubeconfig", readyTimeout, 10*time.Second, func() (bool, string) {
		ready, status := l.readyNodes()
		workers := 0
		for name := range ready {
			if strings.Contains(name, "-small-") && ready[name] {
				workers++
			}
		}
		return workers >= 1, status
	})
	if err != nil {
		return err
	}

	ready, _ := l.readyNodes()
	l.baselineNodes = nil
	for name := range ready {
		l.baselineNodes = append(l.baselineNodes, name)
	}
	l.baselineVMs = l.clusterVMs()
	l.t.Logf("baseline nodes: %v, VMs: %v", l.baselineNodes, l.baselineVMs)
	return nil
}

// --- step 2: overflow → Pending→Running via a new Ready node ------------

func (l *lane) stepOverflowScaleUp() error {
	scaleupTimeout := timeoutEnv("CONTAINARIUM_E2E_SCALEUP_TIMEOUT", 12*time.Minute)
	ctx := context.Background()

	// Two sleepers at 1500m each: one fills the initial small worker
	// (2 CPU), the second cannot fit anywhere and must force a new
	// node. Requests, not load — the autoscaler's currency (design:
	// "Measured utilization triggers no scale-up anywhere").
	replicas := int32(2)
	dep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: "overflow"},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "overflow"}},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "overflow"}},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{
						Name:    "sleep",
						Image:   burnImage,
						Command: []string{"sh", "-c", "sleep infinity"},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("1500m"),
								corev1.ResourceMemory: resource.MustParse("128Mi"),
							},
						},
					}},
				},
			},
		},
	}
	if _, err := l.cs.AppsV1().Deployments("default").Create(ctx, dep, metav1.CreateOptions{}); err != nil {
		return fmt.Errorf("create overflow deployment: %w", err)
	}

	return l.waitFor("overflow Running on a new Ready node", scaleupTimeout, 10*time.Second, func() (bool, string) {
		ready, status := l.readyNodes()
		newNodes := NewReadyNodes(l.baselineNodes, ready)
		pods, err := l.cs.CoreV1().Pods("default").List(ctx, metav1.ListOptions{LabelSelector: "app=overflow"})
		if err != nil {
			return false, err.Error()
		}
		running := 0
		onNew := false
		for _, p := range pods.Items {
			if p.Status.Phase == corev1.PodRunning {
				running++
				for _, n := range newNodes {
					if p.Spec.NodeName == n {
						onNew = true
					}
				}
			}
		}
		return running == int(replicas) && onNew,
			fmt.Sprintf("running=%d/%d newReadyNodes=%v onNew=%v (%s)", running, replicas, newNodes, onNew, status)
	})
}

// --- step 3: a pod too big for the small template -----------------------

func (l *lane) stepLargerClass() error {
	scaleupTimeout := timeoutEnv("CONTAINARIUM_E2E_SCALEUP_TIMEOUT", 12*time.Minute)
	ctx := context.Background()

	// 3 CPU cannot fit the small template (2 CPU): the autoscaler's fit
	// simulation must pick a larger size class, not add another small.
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "big"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:    "sleep",
				Image:   burnImage,
				Command: []string{"sh", "-c", "sleep infinity"},
				Resources: corev1.ResourceRequirements{
					Requests: corev1.ResourceList{
						corev1.ResourceCPU:    resource.MustParse("3"),
						corev1.ResourceMemory: resource.MustParse("256Mi"),
					},
				},
			}},
		},
	}
	if _, err := l.cs.CoreV1().Pods("default").Create(ctx, pod, metav1.CreateOptions{}); err != nil {
		return fmt.Errorf("create big pod: %w", err)
	}

	return l.waitFor("big pod Running on a larger-class node", scaleupTimeout, 10*time.Second, func() (bool, string) {
		p, err := l.cs.CoreV1().Pods("default").Get(ctx, "big", metav1.GetOptions{})
		if err != nil {
			return false, err.Error()
		}
		if p.Status.Phase != corev1.PodRunning {
			return false, fmt.Sprintf("phase=%s node=%s", p.Status.Phase, p.Spec.NodeName)
		}
		larger := strings.Contains(p.Spec.NodeName, "-medium-") || strings.Contains(p.Spec.NodeName, "-large-")
		return larger, fmt.Sprintf("running on %s (larger-class=%v)", p.Spec.NodeName, larger)
	})
}

// --- step 4: VPA raises requests without restart-looping ----------------

var vpaGVR = schema.GroupVersionResource{Group: "autoscaling.k8s.io", Version: "v1", Resource: "verticalpodautoscalers"}

func (l *lane) stepVPA() error {
	vpaTimeout := timeoutEnv("CONTAINARIUM_E2E_VPA_TIMEOUT", 15*time.Minute)
	ctx := context.Background()

	// A burner that actually uses CPU while requesting almost none —
	// VPA is the single component licensed to turn usage into requests.
	replicas := int32(2)
	burn := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: "burner"},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "burner"}},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "burner"}},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{
						Name:    "burn",
						Image:   burnImage,
						Command: []string{"sh", "-c", "while :; do :; done"},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("100m"),
								corev1.ResourceMemory: resource.MustParse("64Mi"),
							},
						},
					}},
				},
			},
		},
	}
	if _, err := l.cs.AppsV1().Deployments("default").Create(ctx, burn, metav1.CreateOptions{}); err != nil {
		return fmt.Errorf("create burner: %w", err)
	}

	// Tenant opt-in, exactly as #1416 documents it: a VPA object with
	// updateMode InPlaceOrRecreate (stock VPA 1.7 on k8s 1.33).
	vpa := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "autoscaling.k8s.io/v1",
		"kind":       "VerticalPodAutoscaler",
		"metadata":   map[string]interface{}{"name": "burner"},
		"spec": map[string]interface{}{
			"targetRef": map[string]interface{}{
				"apiVersion": "apps/v1", "kind": "Deployment", "name": "burner",
			},
			"updatePolicy": map[string]interface{}{
				"updateMode":  "InPlaceOrRecreate",
				"minReplicas": int64(1),
			},
		},
	}}
	if _, err := l.dyn.Resource(vpaGVR).Namespace("default").Create(ctx, vpa, metav1.CreateOptions{}); err != nil {
		return fmt.Errorf("create VPA object (is the VPA bundle deployed?): %w", err)
	}

	before, err := l.restartCounts(ctx, "app=burner")
	if err != nil {
		return err
	}
	origCPU := resource.MustParse("100m")

	var loopErr error
	waitErr := l.waitFor("burner request raised, no restart loop", vpaTimeout, 15*time.Second, func() (bool, string) {
		pods, err := l.cs.CoreV1().Pods("default").List(ctx, metav1.ListOptions{LabelSelector: "app=burner"})
		if err != nil {
			return false, err.Error()
		}
		raised := false
		var seen []string
		for _, p := range pods.Items {
			for _, c := range p.Spec.Containers {
				req := c.Resources.Requests[corev1.ResourceCPU]
				seen = append(seen, fmt.Sprintf("%s=%s", p.Name, req.String()))
				if req.Cmp(origCPU) > 0 {
					raised = true
				}
			}
		}
		after, err := l.restartCounts(ctx, "app=burner")
		if err != nil {
			return false, err.Error()
		}
		delta := MaxRestartDelta(before, after)
		if delta > 1 {
			// Abort the wait with a real error: a raised request via
			// crash-looping is precisely the failure under test.
			loopErr = fmt.Errorf("burner restart-looping: max restart delta %d (requests: %s)", delta, strings.Join(seen, " "))
			return true, "restart loop detected"
		}
		return raised, fmt.Sprintf("requests: %s (restart delta %d)", strings.Join(seen, " "), delta)
	})
	if loopErr != nil {
		return loopErr
	}
	return waitErr
}

// --- step 5: scale to zero → drained node, deleted VM -------------------

func (l *lane) stepScaleToZero() error {
	scaledownTimeout := timeoutEnv("CONTAINARIUM_E2E_SCALEDOWN_TIMEOUT", 30*time.Minute)
	ctx := context.Background()

	// Remove all tenant load. The surplus nodes must drain and their
	// VMs disappear, back to the baseline shape (small group at min=1).
	if err := l.cs.CoreV1().Pods("default").Delete(ctx, "big", metav1.DeleteOptions{}); err != nil {
		return fmt.Errorf("delete big pod: %w", err)
	}
	if err := l.dyn.Resource(vpaGVR).Namespace("default").Delete(ctx, "burner", metav1.DeleteOptions{}); err != nil {
		return fmt.Errorf("delete VPA: %w", err)
	}
	for _, name := range []string{"burner", "overflow"} {
		if err := l.cs.AppsV1().Deployments("default").Delete(ctx, name, metav1.DeleteOptions{}); err != nil {
			return fmt.Errorf("delete %s: %w", name, err)
		}
	}

	baseline := map[string]bool{}
	for _, v := range l.baselineVMs {
		baseline[v] = true
	}

	return l.waitFor("surplus nodes drained and VMs deleted", scaledownTimeout, 20*time.Second, func() (bool, string) {
		// Observed k8s state: the node objects are gone (a drained,
		// deleted node deregisters; a merely cordoned one would linger).
		ready, _ := l.readyNodes()
		surplusNodes := NewReadyNodes(l.baselineNodes, ready)

		// Observed Incus state: no VM beyond the baseline set.
		var surplusVMs []string
		for _, vm := range l.clusterVMs() {
			if !baseline[vm] {
				surplusVMs = append(surplusVMs, vm)
			}
		}
		return len(surplusNodes) == 0 && len(surplusVMs) == 0,
			fmt.Sprintf("surplus nodes=%v surplus VMs=%v", surplusNodes, surplusVMs)
	})
}

// --- step 6: delete leaves nothing --------------------------------------

func (l *lane) stepDelete() error {
	deleteTimeout := timeoutEnv("CONTAINARIUM_E2E_DELETE_TIMEOUT", 10*time.Minute)

	apiHost, err := KubeconfigServerHost(l.kubeconfig)
	if err != nil {
		return err
	}

	if out, err := l.runCLI("cluster", "delete", clusterName); err != nil {
		return fmt.Errorf("cluster delete: %v\n%s", err, out)
	}

	return l.waitFor("no rows, no VMs, no passthrough", deleteTimeout, 10*time.Second, func() (bool, string) {
		// No rows, observed through the product API.
		out, err := l.runCLI("cluster", "get", clusterName)
		if err == nil {
			return false, "cluster get still succeeds"
		}
		if !strings.Contains(strings.ToLower(out), "not") {
			return false, fmt.Sprintf("cluster get: %s", strings.TrimSpace(out))
		}

		// No VMs, observed through Incus.
		if vms := l.clusterVMs(); len(vms) > 0 {
			return false, fmt.Sprintf("VMs remain: %v", vms)
		}

		// No passthrough rule: the published API endpoint stopped
		// accepting connections.
		conn, dialErr := net.DialTimeout("tcp", apiHost, 3*time.Second)
		if dialErr == nil {
			_ = conn.Close()
			return false, fmt.Sprintf("%s still accepts connections", apiHost)
		}
		return true, "gone"
	})
}

// --- sabotage ------------------------------------------------------------

// sabotageJoinTokens continuously corrupts the pre-pushed join token on
// every worker VM and kills any running agent, so no worker can ever
// register: the lane MUST go red. This is the #1418 guardrail — a lane
// that stays green under this cannot fail, and proves nothing.
func (l *lane) sabotageJoinTokens(stop <-chan struct{}) {
	for {
		select {
		case <-stop:
			return
		case <-time.After(3 * time.Second):
		}
		for _, vm := range l.clusterVMs() {
			if strings.HasSuffix(vm, "-cp") {
				continue
			}
			_, _, _ = l.incus.ExecWithOutput(vm, []string{"sh", "-c",
				"echo sabotaged > " + clusterpkg.AgentTokenPath + "; pkill -f 'k3s agent' || true"})
		}
	}
}

// --- observation helpers -------------------------------------------------

// readyNodes returns node name → Ready as observed through the tenant
// kubeconfig, plus a status line for logs.
func (l *lane) readyNodes() (map[string]bool, string) {
	nodes, err := l.cs.CoreV1().Nodes().List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return nil, err.Error()
	}
	out := map[string]bool{}
	var parts []string
	for _, n := range nodes.Items {
		ready := false
		for _, c := range n.Status.Conditions {
			if c.Type == corev1.NodeReady && c.Status == corev1.ConditionTrue {
				ready = true
			}
		}
		out[n.Name] = ready
		parts = append(parts, fmt.Sprintf("%s ready=%v", n.Name, ready))
	}
	return out, strings.Join(parts, ", ")
}

// clusterVMs lists the lane cluster's VMs as Incus sees them.
func (l *lane) clusterVMs() []string {
	all, err := l.incus.ListContainers()
	if err != nil {
		l.t.Logf("incus list: %v", err)
		return nil
	}
	var vms []string
	for _, c := range all {
		if strings.HasPrefix(c.Name, vmPrefix) {
			vms = append(vms, c.Name)
		}
	}
	return vms
}

func (l *lane) restartCounts(ctx context.Context, selector string) (map[string]int32, error) {
	pods, err := l.cs.CoreV1().Pods("default").List(ctx, metav1.ListOptions{LabelSelector: selector})
	if err != nil {
		return nil, err
	}
	out := map[string]int32{}
	for _, p := range pods.Items {
		for _, cs := range p.Status.ContainerStatuses {
			out[p.Name+"/"+cs.Name] = cs.RestartCount
		}
	}
	return out, nil
}

func (l *lane) waitFor(what string, timeout, interval time.Duration, probe func() (bool, string)) error {
	deadline := time.Now().Add(timeout)
	last := ""
	for {
		ok, status := probe()
		if ok {
			l.t.Logf("%s: %s", what, status)
			return nil
		}
		if status != last {
			l.t.Logf("waiting for %s: %s", what, status)
			last = status
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out after %s waiting for %s (last: %s)", timeout, what, status)
		}
		time.Sleep(interval)
	}
}

// dumpDiagnostics prints what the platform and Incus believe on
// failure — the operator's first three commands, run for them.
func (l *lane) dumpDiagnostics() {
	out, err := l.runCLI("cluster", "status", clusterName)
	l.t.Logf("cluster status (err=%v):\n%s", err, out)
	l.t.Logf("incus VMs with prefix %s: %v", vmPrefix, l.clusterVMs())
	if l.cs != nil {
		if evs, err := l.cs.CoreV1().Events("default").List(context.Background(), metav1.ListOptions{Limit: 30}); err == nil {
			var lines []string
			for _, e := range evs.Items {
				lines = append(lines, fmt.Sprintf("%s %s/%s: %s", e.Reason, e.InvolvedObject.Kind, e.InvolvedObject.Name, e.Message))
			}
			l.t.Logf("recent k8s events:\n%s", strings.Join(lines, "\n"))
		}
	}
}
