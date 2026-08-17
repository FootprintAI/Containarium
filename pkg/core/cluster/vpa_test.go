package cluster

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"regexp"
	"strings"
	"testing"
)

// TestVPAPin is the golden pin for what runs inside tenant clusters:
// bundle hash, version, and every image digest-pinned. Re-vendoring
// means changing the bundle AND this test, on purpose.
func TestVPAPin(t *testing.T) {
	m, err := VPAManifests()
	if err != nil {
		t.Fatalf("VPAManifests: %v", err)
	}
	sum := sha256.Sum256(m)
	if hex.EncodeToString(sum[:]) != VPAManifestSHA256 {
		t.Fatal("embedded bundle does not match its pin")
	}
	if VPAVersion != "1.7.1" {
		t.Fatalf("VPAVersion pin changed to %q — re-verify images and manifests against the upstream tag", VPAVersion)
	}

	text := string(m)
	// Every component image is digest-pinned; no floating tags.
	imageRE := regexp.MustCompile(`image:\s*(\S+)`)
	images := imageRE.FindAllStringSubmatch(text, -1)
	if len(images) != 3 {
		t.Fatalf("expected 3 component images, found %d", len(images))
	}
	for _, im := range images {
		if !strings.Contains(im[1], "@sha256:") {
			t.Fatalf("image %q is not digest-pinned", im[1])
		}
	}
	// The bundle carries the three components + the webhook service,
	// and deliberately NOT the TLS secret (generated per cluster).
	for _, must := range []string{"vpa-recommender", "vpa-updater", "vpa-admission-controller", "kind: Service"} {
		if !strings.Contains(text, must) {
			t.Fatalf("bundle missing %q", must)
		}
	}
	if strings.Contains(text, "kind: Secret") {
		t.Fatal("the bundle must not contain a shared TLS secret — it is generated per cluster")
	}
}

func TestGenerateVPAWebhookSecret(t *testing.T) {
	secret, err := GenerateVPAWebhookSecret()
	if err != nil {
		t.Fatal(err)
	}
	text := string(secret)
	for _, must := range []string{"name: vpa-tls-certs", "namespace: kube-system", "caCert.pem:", "serverCert.pem:", "serverKey.pem:"} {
		if !strings.Contains(text, must) {
			t.Fatalf("secret manifest missing %q", must)
		}
	}

	// The serving cert verifies against the CA and carries the
	// webhook service SAN — what the kube-apiserver will check.
	field := func(key string) []byte {
		re := regexp.MustCompile(key + `: (\S+)`)
		m := re.FindStringSubmatch(text)
		if m == nil {
			t.Fatalf("missing %s", key)
		}
		raw, err := base64.StdEncoding.DecodeString(m[1])
		if err != nil {
			t.Fatalf("%s not base64: %v", key, err)
		}
		return raw
	}
	caBlock, _ := pem.Decode(field("caCert.pem"))
	srvBlock, _ := pem.Decode(field("serverCert.pem"))
	if caBlock == nil || srvBlock == nil {
		t.Fatal("certs are not PEM")
	}
	ca, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := x509.ParseCertificate(srvBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	if _, err := srv.Verify(x509.VerifyOptions{
		Roots:     pool,
		DNSName:   "vpa-webhook.kube-system.svc",
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		t.Fatalf("serving cert does not verify for the webhook service: %v", err)
	}

	// Two clusters never share webhook certs.
	secret2, err := GenerateVPAWebhookSecret()
	if err != nil {
		t.Fatal(err)
	}
	if string(secret) == string(secret2) {
		t.Fatal("webhook secrets are identical across generations")
	}
}

func TestDeployVPA(t *testing.T) {
	f := newFakeHost()
	f.readErr = errNotDeployed{}
	m := testManager(f)

	if err := m.DeployVPA("alice", "demo"); err != nil {
		t.Fatalf("DeployVPA: %v", err)
	}
	cp := "alice-k8s-demo-cp"
	if _, ok := f.files[cp+":"+VPAManifestPath]; !ok {
		t.Fatal("VPA manifests not pushed")
	}
	if _, ok := f.files[cp+":"+VPACertsPath]; !ok {
		t.Fatal("VPA certs manifest not pushed")
	}

	// Idempotent: a second deploy must NOT regenerate the secret —
	// that would rotate the webhook's certs under the running
	// admission controller.
	f.readErr = nil // certs file now readable
	before := string(f.files[cp+":"+VPACertsPath])
	if err := m.DeployVPA("alice", "demo"); err != nil {
		t.Fatalf("second DeployVPA: %v", err)
	}
	if string(f.files[cp+":"+VPACertsPath]) != before {
		t.Fatal("second deploy rotated the webhook secret")
	}
}

type errNotDeployed struct{}

func (errNotDeployed) Error() string { return "no such file" }
