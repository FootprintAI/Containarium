package cluster

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

// Vertical Pod Autoscaler (#1416): upstream VPA shipped into every
// managed cluster via the k3s manifest auto-apply dir. Usage→requests
// conversion happens ONLY here (design: "Who decides what"); tenants
// opt workloads in with VPA objects (updateMode InPlaceOrRecreate for
// in-place resizes, Recreate as the fallback — both stock VPA 1.7
// behavior, no bespoke resizing loop).
const (
	// VPAVersion is the pinned upstream release.
	VPAVersion = "1.7.1"
	// VPAManifestSHA256 pins the embedded, digest-pinned manifest
	// bundle — the reviewable surface (golden-tested like the k3s
	// binary pin): what runs inside tenant clusters changes only as
	// a visible re-vendor diff.
	VPAManifestSHA256 = "a74ea4c0e47561d4fd0bb9003a5e005dd5eb43fe173161b7dd86ff97ffebecd4"
)

//go:embed vpa/manifests.yaml
var vpaManifests []byte

// VPAManifests returns the vendored bundle after re-verifying it
// against the pin — a tampered or drifted embed fails closed instead
// of being applied into a tenant's cluster.
func VPAManifests() ([]byte, error) {
	sum := sha256.Sum256(vpaManifests)
	if got := hex.EncodeToString(sum[:]); got != VPAManifestSHA256 {
		return nil, fmt.Errorf("embedded VPA manifests hash %s does not match the pin %s", got, VPAManifestSHA256)
	}
	return vpaManifests, nil
}

// K3s manifest auto-apply paths for the VPA deployment.
const (
	VPAManifestPath = "/var/lib/rancher/k3s/server/manifests/containarium-vpa.yaml"
	VPACertsPath    = "/var/lib/rancher/k3s/server/manifests/containarium-vpa-certs.yaml"
)

// vpaWebhookDNS is the admission webhook's in-cluster service name —
// the SAN its serving cert must carry.
const vpaWebhookDNS = "vpa-webhook.kube-system.svc"

// GenerateVPAWebhookSecret generates a fresh per-cluster CA + serving
// cert for the VPA admission webhook and renders the vpa-tls-certs
// Secret (key names are the admission-controller's flag defaults).
// Per-cluster generation, never shared, never persisted by the
// platform — the Secret lives only inside the tenant's cluster.
func GenerateVPAWebhookSecret() ([]byte, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          vpaSerial(),
		Subject:               pkix.Name{CommonName: "containarium vpa-webhook CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, err
	}

	srvKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	srvTmpl := &x509.Certificate{
		SerialNumber: vpaSerial(),
		Subject:      pkix.Name{CommonName: vpaWebhookDNS},
		DNSNames:     []string{vpaWebhookDNS, vpaWebhookDNS + ".cluster.local"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	srvDER, err := x509.CreateCertificate(rand.Reader, srvTmpl, caCert, &srvKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	srvKeyDER, err := x509.MarshalPKCS8PrivateKey(srvKey)
	if err != nil {
		return nil, err
	}

	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	srvPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srvDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: srvKeyDER})

	b64 := base64.StdEncoding.EncodeToString
	secret := fmt.Sprintf(`# Generated per cluster by containarium (#1416). The admission
# webhook's serving certs — never shared across clusters.
apiVersion: v1
kind: Secret
metadata:
  name: vpa-tls-certs
  namespace: kube-system
type: Opaque
data:
  caCert.pem: %s
  serverCert.pem: %s
  serverKey.pem: %s
`, b64(caPEM), b64(srvPEM), b64(keyPEM))
	return []byte(secret), nil
}

func vpaSerial() *big.Int {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		panic(err) // rand.Reader failing is unrecoverable
	}
	return serial
}

// DeployVPA installs the pinned VPA bundle onto a provisioned control
// plane via the k3s auto-apply dir. Idempotent by presence check: the
// per-cluster webhook Secret is generated exactly once — re-pushing it
// every pass would rotate the webhook's certs under the running
// admission controller.
func (m *Manager) DeployVPA(tenant, clusterName string) error {
	cp := CPName(tenant, clusterName)
	if _, err := m.host.Read(cp, VPACertsPath); err == nil {
		return nil // already deployed
	}
	manifests, err := VPAManifests()
	if err != nil {
		return err
	}
	secret, err := GenerateVPAWebhookSecret()
	if err != nil {
		return fmt.Errorf("generate VPA webhook certs: %w", err)
	}
	if err := m.pushFile(cp, VPACertsPath, secret, "0600"); err != nil {
		return fmt.Errorf("push VPA certs manifest: %w", err)
	}
	if err := m.pushFile(cp, VPAManifestPath, manifests, "0644"); err != nil {
		return fmt.Errorf("push VPA manifests: %w", err)
	}
	return nil
}
