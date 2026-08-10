package server

import (
	"context"
	"strings"
	"testing"

	"github.com/footprintai/containarium/internal/secrets"
	"github.com/footprintai/containarium/pkg/core/box"
	"github.com/footprintai/containarium/pkg/core/container"
)

// #1190: on K8s, `secret set` succeeded and the value never reached the box.
// These cover the translation from stored rows to what the box mounts —
// the step where a delivery mode can be silently dropped.

type fakeApplier struct {
	data map[string][]byte
	err  error
}

func (f *fakeApplier) ApplyTenantSecrets(_ context.Context, _ string, data map[string][]byte) error {
	if f.err != nil {
		return f.err
	}
	f.data = data
	return nil
}

// deliverK8s runs the K8s translation over a fixed set of stored rows,
// without a database.
func deliverK8s(t *testing.T, rows map[string]secrets.SecretValue) *fakeApplier {
	t.Helper()
	applier := &fakeApplier{}
	if err := applier.ApplyTenantSecrets(context.Background(), "alice", secretsToK8sData(rows)); err != nil {
		t.Fatalf("deliver: %v", err)
	}
	return applier
}

func TestK8sDelivery_EnvAndFileRowsBothBecomeFiles(t *testing.T) {
	applier := deliverK8s(t, map[string]secrets.SecretValue{
		"API_TOKEN": {Value: "tok", Delivery: secrets.DeliveryEnv},
		"TLS_KEY":   {Value: "pem", Delivery: secrets.DeliveryFile},
	})

	if string(applier.data["API_TOKEN"]) != "tok" {
		t.Errorf("env-mode secret = %q, want its value — an env row dropped here is exactly the "+
			"silent non-delivery #1190 is about", applier.data["API_TOKEN"])
	}
	if string(applier.data["TLS_KEY"]) != "pem" {
		t.Errorf("file-mode secret = %q, want its value", applier.data["TLS_KEY"])
	}
}

// Compose rows are consumed as one dotenv file. Carrying them across as
// individual keys, or dropping them, would each break a compose app.
func TestK8sDelivery_ComposeRowsBecomeOneDotenvFile(t *testing.T) {
	applier := deliverK8s(t, map[string]secrets.SecretValue{
		"DB_PASS": {Value: "p1", Delivery: secrets.DeliveryCompose},
		"DB_USER": {Value: "u1", Delivery: secrets.DeliveryCompose},
	})

	dotenv, ok := applier.data[composeSecretKey]
	if !ok {
		t.Fatalf("no compose dotenv delivered; keys=%v — a compose app would come up with no "+
			"credentials and no error", keysOf(applier.data))
	}
	body := string(dotenv)
	if !strings.Contains(body, "DB_USER=u1") || !strings.Contains(body, "DB_PASS=p1") {
		t.Errorf("dotenv is missing values:\n%s", body)
	}
	// Individual keys too would put the same secret in the box twice, under
	// two names, and only one of them documented.
	if _, dup := applier.data["DB_PASS"]; dup {
		t.Error("a compose row was also delivered as its own file")
	}
}

// The rendered dotenv must be byte-identical between deliveries, or every
// pass looks like a change and rewrites the Secret.
func TestK8sDelivery_DotenvIsStableAcrossDeliveries(t *testing.T) {
	rows := map[string]secrets.SecretValue{
		"A": {Value: "1", Delivery: secrets.DeliveryCompose},
		"B": {Value: "2", Delivery: secrets.DeliveryCompose},
		"C": {Value: "3", Delivery: secrets.DeliveryCompose},
	}
	first := string(deliverK8s(t, rows).data[composeSecretKey])
	for i := 0; i < 8; i++ {
		if got := string(deliverK8s(t, rows).data[composeSecretKey]); got != first {
			t.Fatalf("dotenv differs between deliveries:\n%q\nvs\n%q\n"+
				"map iteration order would make every reconcile look like a change", first, got)
		}
	}
}

// The compose file must be the same shape on both backends, so an app's
// env_file reference differs only in directory.
func TestK8sDelivery_ComposeFileMatchesTheLXCRendering(t *testing.T) {
	rows := map[string]secrets.SecretValue{
		"A": {Value: "1", Delivery: secrets.DeliveryCompose},
		"B": {Value: "2", Delivery: secrets.DeliveryCompose},
	}
	got := deliverK8s(t, rows).data[composeSecretKey]
	want := container.RenderEnvFile(container.SecretsEnvFile.Header,
		map[string]string{"A": "1", "B": "2"})

	if string(got) != string(want) {
		t.Errorf("the K8s compose file differs from the LXC one:\n%q\nvs\n%q", got, want)
	}
	if composeSecretKey != "secrets.env" {
		t.Errorf("compose file is named %q; it should match the LXC path's basename so an "+
			"env_file: reference differs only in directory", composeSecretKey)
	}
}

// A tenant with no secrets must translate to an empty set, because that is
// what makes the apply delete the object instead of leaving the last values
// mounted. Deleting the last secret and having it stay readable would be a
// deletion that reports success and does nothing.
//
// (Only the translation is asserted here. That an empty set actually deletes
// the object is the applier's job and is covered in pkg/core/box/k8s. Calling
// the fake applier and asserting it was called once would prove nothing —
// this test calls it directly.)
func TestK8sDelivery_NoSecretsTranslatesToAnEmptySet(t *testing.T) {
	if got := secretsToK8sData(map[string]secrets.SecretValue{}); len(got) != 0 {
		t.Errorf("translated a tenant with no secrets to %d key(s): %v", len(got), keysOf(got))
	}
	// A tenant whose only secrets were compose rows, all now deleted, must
	// also land on empty — not on a lone empty dotenv that keeps the object
	// alive.
	if got := secretsToK8sData(nil); len(got) != 0 {
		t.Errorf("translated a nil row set to %d key(s): %v", len(got), keysOf(got))
	}
}

func keysOf(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// The refresh message is the only feedback an operator gets that delivery
// happened. Naming the LXC mechanism and an object that does not exist on
// K8s would tell them their secrets landed somewhere they cannot find.
func TestRefreshMessage_DescribesTheBackendItRanOn(t *testing.T) {
	k8s := refreshSecretsMessage(box.KindK8s, "alice", 3)
	lxc := refreshSecretsMessage(box.KindLXC, "alice", 3)

	if strings.Contains(k8s, "alice-container") {
		t.Errorf("the K8s message names a container that does not exist there: %q", k8s)
	}
	if strings.Contains(k8s, "re-stamped") {
		t.Errorf("the K8s message describes the LXC mechanism: %q", k8s)
	}
	if !strings.Contains(lxc, "alice-container") {
		t.Errorf("the LXC message no longer names the container: %q", lxc)
	}
	for name, msg := range map[string]string{"k8s": k8s, "lxc": lxc} {
		if !strings.Contains(msg, "3") {
			t.Errorf("%s message does not say how many secrets were delivered: %q", name, msg)
		}
	}
}
