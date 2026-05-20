// Package pki implements the Containarium peer-CA used to issue
// short-lived certificates for sentinel↔daemon and peer-to-peer
// HTTPS. Design summary: a single operator-managed RSA private
// key on the sentinel acts as the CA, the CA certificate is
// generated at runtime from that key, and per-peer client/server
// certs are minted on demand with a configurable short TTL
// (default 7 days). No CRL or OCSP — rotation happens before any
// leaf could be meaningfully abused.
//
// The pattern intentionally avoids:
//   - Bundling a separate ca.crt file (only the key needs storing).
//   - An enrollment ceremony with PKCS#10 CSRs (overkill for a
//     two-tier control-plane / data-plane topology where peer
//     identity is already established at the tunnel layer).
//   - Long-lived end-entity certs (a fleet that can lose a daemon
//     for 7 days has bigger problems than cert rotation).
//
// Cert-building primitives are reused from
// github.com/footprintai/go-certs/pkg/certs/gen — the same
// library already used for the daemon's gRPC mTLS path
// (internal/mtls/loader.go). What we add on top is the "CA cert
// is regenerated at runtime from just the key" ergonomics, which
// keeps operators to one secret file instead of two.
//
// See docs/security/ZERO-TRUST-AUDIT.md C-CRIT-1 for the threat
// model this package closes.
package pki

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"net"
	"time"

	certsgen "github.com/footprintai/go-certs/pkg/certs/gen"
)

// DefaultLeafExpiry is the default TTL for peer / server
// end-entity certs. Short enough that a leaked key has limited
// blast radius; long enough that an off-by-a-day clock won't
// brick the fleet. Renewal kicks in at 2/3 of this.
const DefaultLeafExpiry = 7 * 24 * time.Hour

// CAValidity is the lifetime of the self-signed CA cert generated
// at runtime from the operator's RSA key. 10 years is long enough
// that the CA cert itself never expires in normal operation; the
// only durable secret is the RSA key on disk, which the operator
// rotates by replacing the file and restarting the sentinel.
const CAValidity = 10 * 365 * 24 * time.Hour

// orgName goes into the Subject of every cert this CA issues —
// looks intelligible in `openssl x509 -text` output during
// incident response.
const orgName = "Containarium CA"

// Provisioner issues per-peer X.509 certificates signed by the
// sentinel's CA. Only the sentinel holds the CA private key;
// daemons receive only the CA certificate (for verification) and
// their own leaf cert + key (for mTLS).
type Provisioner struct {
	caCert    *x509.Certificate
	caKey     *rsa.PrivateKey
	caCertPEM []byte
	expiry    time.Duration
}

// NewFromKey builds a Provisioner from just the CA private key.
// The CA certificate is generated at runtime — operators only need
// to manage the key file (mode 0400, single backup, off-host copy
// for disaster recovery).
//
// `caKeyPEM` must be either an "RSA PRIVATE KEY" (PKCS#1) or a
// "PRIVATE KEY" (PKCS#8) block. `expiry` is the leaf TTL; pass 0
// to use DefaultLeafExpiry.
func NewFromKey(caKeyPEM []byte, expiry time.Duration) (*Provisioner, error) {
	caKey, err := parseRSAKey(caKeyPEM)
	if err != nil {
		return nil, err
	}
	if expiry <= 0 {
		expiry = DefaultLeafExpiry
	}

	// Use certsgen.CertTemplate for the serial-number + base
	// fields, then mark this template as a self-signed CA. (The
	// library doesn't expose a "make me a CA template" helper, so
	// we set the CA-specific bits ourselves — short and explicit.)
	now := time.Now()
	caTemplate, err := certsgen.CertTemplate(
		now.Add(-1*time.Minute), // backdate to absorb sentinel↔daemon clock skew
		now.Add(CAValidity),
		certsgen.WithOrganizations(orgName),
	)
	if err != nil {
		return nil, fmt.Errorf("CA cert template: %w", err)
	}
	caTemplate.Subject.CommonName = "Containarium Peer CA"
	caTemplate.IsCA = true
	caTemplate.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	caTemplate.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}

	caCert, caCertPEM, err := certsgen.CreateCert(caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("create CA cert: %w", err)
	}

	return &Provisioner{
		caCert:    caCert,
		caKey:     caKey,
		caCertPEM: caCertPEM,
		expiry:    expiry,
	}, nil
}

// IssuePeerCert mints a leaf certificate for the named peer.
// Returns PEM-encoded cert and key (PKCS#1). The cert carries both
// `clientAuth` and `serverAuth` extended key usages so the same
// pair works whether the peer is the TLS client (calling another
// peer) or the TLS server (receiving a call). `peerID` lands in
// the Common Name and as a DNS SAN — the verifying side checks the
// SAN against the expected peer ID.
//
// `extraSANs` lets callers add hostnames (e.g. the sentinel's
// public FQDN, or a peer's loopback alias) without restricting to
// a fixed list — pass nil for peer-leaf certs where the ID is
// sufficient.
func (p *Provisioner) IssuePeerCert(peerID string, extraSANs []string, extraIPs []net.IP) (certPEM, keyPEM []byte, err error) {
	if peerID == "" {
		return nil, nil, fmt.Errorf("peerID is required")
	}
	template, err := p.leafTemplate(extraSANs, extraIPs)
	if err != nil {
		return nil, nil, err
	}
	template.Subject = pkix.Name{CommonName: peerID, Organization: []string{orgName}}
	// Inject peerID as the first SAN so the verifying side can
	// pass the expected ID via tls.Config.ServerName.
	template.DNSNames = append([]string{peerID}, template.DNSNames...)
	template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
	template.AuthorityKeyId = p.caCert.SubjectKeyId

	return p.signLeaf(template)
}

// IssueSentinelServerCert mints a server cert for the sentinel
// itself. Use this for the HTTPS binary-server listener (where
// daemons connect to fetch peer discovery, CA, and through which
// peer-to-peer traffic is proxied). The cert carries the supplied
// DNS names and IPs as SANs — pass the sentinel's publicly
// reachable hostname plus any internal/loopback aliases.
func (p *Provisioner) IssueSentinelServerCert(dnsNames []string, ipAddrs []net.IP) (certPEM, keyPEM []byte, err error) {
	template, err := p.leafTemplate(dnsNames, ipAddrs)
	if err != nil {
		return nil, nil, err
	}
	template.Subject = pkix.Name{CommonName: "containarium-sentinel", Organization: []string{orgName}}
	template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	template.AuthorityKeyId = p.caCert.SubjectKeyId

	return p.signLeaf(template)
}

// leafTemplate builds a base x509 template for a leaf cert with
// the configured TTL and the given SANs. Caller fills in Subject
// + ExtKeyUsage + AuthorityKeyId before signing.
func (p *Provisioner) leafTemplate(dnsNames []string, ipAddrs []net.IP) (*x509.Certificate, error) {
	now := time.Now()
	stringIPs := make([]string, 0, len(ipAddrs))
	for _, ip := range ipAddrs {
		stringIPs = append(stringIPs, ip.String())
	}
	tmpl, err := certsgen.CertTemplate(
		now.Add(-1*time.Minute),
		now.Add(p.expiry),
		certsgen.WithOrganizations(orgName),
		certsgen.WithAliasDNSNames(dnsNames...),
		certsgen.WithAliasIPs(stringIPs...),
	)
	if err != nil {
		return nil, fmt.Errorf("leaf cert template: %w", err)
	}
	tmpl.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	tmpl.BasicConstraintsValid = true
	return tmpl, nil
}

// signLeaf signs `template` with the CA and returns PEM cert + key.
func (p *Provisioner) signLeaf(template *x509.Certificate) (certPEM, keyPEM []byte, err error) {
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("generate leaf key: %w", err)
	}
	_, certPEM, err = certsgen.CreateCert(template, p.caCert, &leafKey.PublicKey, p.caKey)
	if err != nil {
		return nil, nil, fmt.Errorf("sign leaf cert: %w", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(leafKey)})
	return certPEM, keyPEM, nil
}

// CACertPEM returns the CA certificate in PEM form. Daemons pin
// this for peer-to-peer verification; never return the CA key.
func (p *Provisioner) CACertPEM() []byte {
	return p.caCertPEM
}

// LeafExpiry returns the configured leaf TTL. Useful for setting
// up renewal timers.
func (p *Provisioner) LeafExpiry() time.Duration {
	return p.expiry
}

func parseRSAKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("decode CA key PEM: no PEM block found")
	}
	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse PKCS#8 key: %w", err)
		}
		rsaKey, ok := k.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("CA key is not RSA")
		}
		return rsaKey, nil
	default:
		return nil, fmt.Errorf("unsupported CA key PEM type %q (want RSA PRIVATE KEY or PRIVATE KEY)", block.Type)
	}
}
