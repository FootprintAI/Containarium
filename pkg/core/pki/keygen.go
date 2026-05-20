package pki

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// GenerateCAKey produces a fresh RSA-4096 private key suitable for
// use as the Containarium peer-CA root. The returned bytes are PEM-
// encoded ("RSA PRIVATE KEY" / PKCS#1) and should be written to
// disk mode 0400 on the sentinel.
//
// 4096 bits matches the durability of the 10-year CA cert
// auto-generated from this key (see CAValidity). End-entity certs
// are 2048-bit RSA in IssuePeerCert / IssueSentinelServerCert — a
// reasonable compromise of issuance speed vs. strength given their
// 7-day lifetime.
//
// Operators bootstrap a fresh sentinel with:
//
//	containarium cert generate-ca > /etc/containarium/ca.key
//	chmod 0400 /etc/containarium/ca.key
//
// And then point the sentinel at it with CONTAINARIUM_CA_KEY_FILE.
func GenerateCAKey() ([]byte, error) {
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, fmt.Errorf("generate RSA-4096 key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}), nil
}
