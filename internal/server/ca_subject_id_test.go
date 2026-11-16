//go:build !containarium_client

package server

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	clusterstore "github.com/footprintai/containarium/internal/cluster"
)

// The cluster identity carries the cluster's immutable id (#3689, stage 2). A
// certificate for a cluster deleted and recreated under the same name must not
// match the new cluster; a legacy name-only subject is still accepted.

func TestCASubjectRoundTripsTheId(t *testing.T) {
	owner, name, id, err := parseCASubject(CASubject("alice", "demo", "id-1"))
	if err != nil || owner != "alice" || name != "demo" || id != "id-1" {
		t.Fatalf("round trip = %q %q %q %v, want alice demo id-1", owner, name, id, err)
	}
	owner, name, id, err = parseCASubject(CASubject("alice", "demo", ""))
	if err != nil || owner != "alice" || name != "demo" || id != "" {
		t.Fatalf("legacy subject = %q %q %q %v, want alice demo empty", owner, name, id, err)
	}
	for _, bad := range []string{"k8s-cluster:alice", "k8s-cluster:/demo#id", "alice/demo#id"} {
		if _, _, _, err := parseCASubject(bad); err == nil {
			t.Errorf("parseCASubject(%q) accepted a malformed subject", bad)
		}
	}
}

func TestBoundClusterRefusesARecreatedCluster(t *testing.T) {
	ctx := context.Background()
	store := clusterstore.NewMemStore()
	if err := store.Create(ctx, &clusterstore.Cluster{ID: "new-id", Owner: "alice", Name: "demo"}); err != nil {
		t.Fatal(err)
	}
	s := NewCAProviderServer(store, nil)

	if _, err := s.boundCluster(ctx, "alice", "demo", "old-id"); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("certificate for the old cluster: err = %v, want PermissionDenied", err)
	}
	if _, err := s.boundCluster(ctx, "alice", "demo", "new-id"); err != nil {
		t.Fatalf("certificate for the current cluster: %v", err)
	}
	// A name-only certificate carries no id, so it cannot match the current
	// cluster and is refused (#3689 stage 3b).
	if _, err := s.boundCluster(ctx, "alice", "demo", ""); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("name-only certificate: err = %v, want PermissionDenied", err)
	}
}

func TestMintedCertCarriesTheClusterId(t *testing.T) {
	pki, err := LoadOrCreateClusterPKI(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	certPEM, _, err := pki.MintClientCert("alice", "demo", "id-1")
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("no PEM block in the minted certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if want := CASubject("alice", "demo", "id-1"); cert.Subject.CommonName != want {
		t.Errorf("CN = %q, want %q", cert.Subject.CommonName, want)
	}
}
