package auth

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// Phase 2.1 — RequireMTLSUnaryInterceptor must reject calls
// without a verified mTLS peer. Audit finding C-HIGH-2.

func TestAssertMTLSPeer_NoPeerInfo(t *testing.T) {
	err := assertMTLSPeer(context.Background())
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("want Unauthenticated, got %v (%v)", status.Code(err), err)
	}
}

func TestAssertMTLSPeer_NonTLSPeer(t *testing.T) {
	// peer with no AuthInfo (plaintext connection).
	ctx := peer.NewContext(context.Background(), &peer.Peer{
		AuthInfo: nil,
	})
	err := assertMTLSPeer(ctx)
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("plaintext peer must be rejected; got %v", err)
	}
}

func TestAssertMTLSPeer_TLSWithoutClientCert(t *testing.T) {
	// TLS connection but no verified client cert — e.g. server-only
	// TLS without mTLS. Must be rejected for the mTLS path.
	ctx := peer.NewContext(context.Background(), &peer.Peer{
		AuthInfo: credentials.TLSInfo{
			State: tls.ConnectionState{
				// No VerifiedChains populated.
			},
		},
	})
	err := assertMTLSPeer(ctx)
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("TLS-without-client-cert must be rejected; got %v", err)
	}
}

func TestAssertMTLSPeer_VerifiedClientCert(t *testing.T) {
	// Synthesize a fake verified chain — the interceptor just
	// checks for presence, doesn't re-verify (that's gRPC's job).
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-peer"},
	}
	ctx := peer.NewContext(context.Background(), &peer.Peer{
		AuthInfo: credentials.TLSInfo{
			State: tls.ConnectionState{
				VerifiedChains: [][]*x509.Certificate{{cert}},
			},
		},
	})
	if err := assertMTLSPeer(ctx); err != nil {
		t.Fatalf("verified client cert must pass: %v", err)
	}
}

func TestMTLSPeerCN_ReturnsCommonName(t *testing.T) {
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "tunnel-fts-5900x-gpu"},
	}
	ctx := peer.NewContext(context.Background(), &peer.Peer{
		AuthInfo: credentials.TLSInfo{
			State: tls.ConnectionState{
				VerifiedChains: [][]*x509.Certificate{{cert}},
			},
		},
	})
	cn, err := MTLSPeerCN(ctx)
	if err != nil {
		t.Fatalf("MTLSPeerCN: %v", err)
	}
	if cn != "tunnel-fts-5900x-gpu" {
		t.Fatalf("CN = %q, want tunnel-fts-5900x-gpu", cn)
	}
}

func TestMTLSPeerCN_NoPeerErrors(t *testing.T) {
	_, err := MTLSPeerCN(context.Background())
	if err == nil {
		t.Fatal("MTLSPeerCN must error when no peer info")
	}
	if !errors.Is(err, err) { //nolint:gosimple // just a sanity reference
		// keeps the variable from being flagged as unused if err
		// shape changes later
	}
}
