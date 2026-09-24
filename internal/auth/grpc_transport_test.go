package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// pki is a throwaway CA plus a server identity for 127.0.0.1.
type pki struct {
	ca         *x509.Certificate
	caKey      *ecdsa.PrivateKey
	pool       *x509.CertPool
	serverCert tls.Certificate
}

func newPKI(t *testing.T) *pki {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(der)
	p := &pki{ca: ca, caKey: caKey, pool: x509.NewCertPool()}
	p.pool.AddCert(ca)
	p.serverCert = p.issue(t, "server", x509.ExtKeyUsageServerAuth, net.ParseIP("127.0.0.1"))
	return p
}

func (p *pki) issue(t *testing.T, cn string, usage x509.ExtKeyUsage, ip net.IP) tls.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage},
	}
	if ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.ca, &key.PublicKey, p.caKey)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func (p *pki) serverCreds() credentials.TransportCredentials {
	return credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{p.serverCert},
		ClientCAs:    p.pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
	})
}

func (p *pki) clientCreds(withCert *tls.Certificate) credentials.TransportCredentials {
	cfg := &tls.Config{RootCAs: p.pool, MinVersion: tls.VersionTLS12}
	if withCert != nil {
		cfg.Certificates = []tls.Certificate{*withCert}
	}
	return credentials.NewTLS(cfg)
}

const (
	adminOpMethod = "/authtest.Svc/AdminOp"
	whoamiMethod  = "/authtest.Svc/Whoami"
)

// startServer wires the production credentials and interceptors around two
// stand-in RPCs: AdminOp applies the guard sensitive RPCs use; Whoami echoes
// the identity the handler sees.
func startServer(t *testing.T, tlsCreds credentials.TransportCredentials) (tcpAddr string, internal *InternalListener) {
	t.Helper()
	return startServerTCP(t, tlsCreds, tlsCreds != nil)
}

// startServerTCP optionally attaches a TCP listener even when tlsCreds is nil,
// to prove the handshake refuses external connections on its own (the daemon
// simply doesn't open that listener without --mtls).
func startServerTCP(t *testing.T, tlsCreds credentials.TransportCredentials, tcp bool) (tcpAddr string, internal *InternalListener) {
	t.Helper()
	// Like generated handlers, these must run the server interceptor chain
	// (the 4th argument); a handler that ignores it would bypass the code
	// under test.
	handle := func(fullMethod string, impl func(context.Context) (interface{}, error)) func(interface{}, context.Context, func(interface{}) error, grpc.UnaryServerInterceptor) (interface{}, error) {
		return func(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
			in := new(emptypb.Empty)
			if err := dec(in); err != nil {
				return nil, err
			}
			h := func(ctx context.Context, _ interface{}) (interface{}, error) { return impl(ctx) }
			if interceptor == nil {
				return h(ctx, in)
			}
			return interceptor(ctx, in, &grpc.UnaryServerInfo{Server: srv, FullMethod: fullMethod}, h)
		}
	}
	adminOp := handle(adminOpMethod, func(ctx context.Context) (interface{}, error) {
		if err := RequireRole(ctx, RoleAdmin); err != nil {
			return nil, err
		}
		return &emptypb.Empty{}, nil
	})
	whoami := handle(whoamiMethod, func(ctx context.Context) (interface{}, error) {
		u, roles, _ := SubjectFromGRPCContext(ctx)
		return wrapperspb.String(u + "|" + strings.Join(roles, ",")), nil
	})
	desc := grpc.ServiceDesc{
		ServiceName: "authtest.Svc",
		HandlerType: (*interface{})(nil),
		Methods:     []grpc.MethodDesc{{MethodName: "AdminOp", Handler: adminOp}, {MethodName: "Whoami", Handler: whoami}},
	}
	srv := grpc.NewServer(
		grpc.Creds(NewServerTransportCredentials(tlsCreds)),
		grpc.ChainUnaryInterceptor(TransportIdentityUnaryInterceptor()),
	)
	srv.RegisterService(&desc, struct{}{})
	internal = NewInternalListener()
	go func() { _ = srv.Serve(internal) }()
	if tcp {
		lis, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		tcpAddr = lis.Addr().String()
		go func() { _ = srv.Serve(lis) }()
	}
	t.Cleanup(srv.Stop)
	return tcpAddr, internal
}

func invoke(t *testing.T, cc *grpc.ClientConn, method string, out interface{}, md metadata.MD) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if md != nil {
		ctx = metadata.NewOutgoingContext(ctx, md)
	}
	return cc.Invoke(ctx, method, &emptypb.Empty{}, out)
}

func dialTCP(t *testing.T, addr string, creds credentials.TransportCredentials) *grpc.ClientConn {
	t.Helper()
	cc, err := grpc.NewClient(addr, grpc.WithTransportCredentials(creds))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cc.Close() })
	return cc
}

func forgedAdmin() metadata.MD {
	return metadata.Pairs(MDKeyUsername, "attacker", MDKeyRoles, RoleAdmin, MDKeyScopes, "*")
}

// Regression: a client with no credential must not pass an admin guard by
// asserting identity metadata. With mTLS off there is no external listener.
func TestExternalPlaintextClientCannotAssertIdentity(t *testing.T) {
	// mTLS on, so a TCP listener exists; a plaintext client must be refused.
	p := newPKI(t)
	addr, _ := startServer(t, p.serverCreds())
	cc := dialTCP(t, addr, insecure.NewCredentials())
	if err := invoke(t, cc, adminOpMethod, &emptypb.Empty{}, forgedAdmin()); err == nil {
		t.Fatal("plaintext client with forged admin metadata was accepted")
	}
}

func TestExternalTLSWithoutClientCertRejected(t *testing.T) {
	p := newPKI(t)
	addr, _ := startServer(t, p.serverCreds())
	cc := dialTCP(t, addr, p.clientCreds(nil))
	if err := invoke(t, cc, adminOpMethod, &emptypb.Empty{}, forgedAdmin()); err == nil {
		t.Fatal("TLS client without a client certificate was accepted")
	}
}

func TestNoTLSConfiguredRefusesAllExternalConnections(t *testing.T) {
	addr, _ := startServerTCP(t, nil, true)
	cc := dialTCP(t, addr, insecure.NewCredentials())
	if err := invoke(t, cc, adminOpMethod, &emptypb.Empty{}, forgedAdmin()); err == nil {
		t.Fatal("external plaintext connection accepted with no TLS configured")
	}
}

// With a valid client certificate, identity comes from the certificate; the
// client's own identity metadata is discarded, so it cannot escalate.
func TestMTLSPeerIdentityComesFromCertNotMetadata(t *testing.T) {
	p := newPKI(t)
	addr, _ := startServer(t, p.serverCreds())
	cert := p.issue(t, "operator-1", x509.ExtKeyUsageClientAuth, nil)
	cc := dialTCP(t, addr, p.clientCreds(&cert))

	if err := invoke(t, cc, adminOpMethod, &emptypb.Empty{}, forgedAdmin()); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("forged admin over mTLS: want PermissionDenied, got %v", err)
	}
	var who wrapperspb.StringValue
	if err := invoke(t, cc, whoamiMethod, &who, forgedAdmin()); err != nil {
		t.Fatal(err)
	}
	if who.Value != "mtls:operator-1|" {
		t.Fatalf("handler saw identity %q; want cert-derived %q with no roles", who.Value, "mtls:operator-1|")
	}
}

// The daemon's REST gateway reaches the server through the in-process
// listener, and its forwarded (JWT-verified) claims must keep working.
func TestInternalListenerTrustsForwardedClaims(t *testing.T) {
	_, internal := startServer(t, nil)
	cc, err := grpc.NewClient("passthrough:///internal",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(internal.DialContext))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cc.Close() }()
	if err := invoke(t, cc, adminOpMethod, &emptypb.Empty{}, metadata.Pairs(MDKeyUsername, "alice", MDKeyRoles, RoleAdmin)); err != nil {
		t.Fatalf("gateway-forwarded admin claims rejected: %v", err)
	}
	if err := invoke(t, cc, adminOpMethod, &emptypb.Empty{}, metadata.Pairs(MDKeyUsername, "bob", MDKeyRoles, "user")); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("non-admin: want PermissionDenied, got %v", err)
	}
}

func TestReservedIdentityMetadataKeys(t *testing.T) {
	for _, k := range []string{"username", "Roles", "SCOPES", "act", "jti", "run_id", "tracker_conn", "x-containarium-gateway-forward"} {
		if !IsReservedIdentityMetadataKey(k) {
			t.Errorf("%q must be reserved", k)
		}
	}
	if IsReservedIdentityMetadataKey("content-type") {
		t.Error("content-type must not be reserved")
	}
}
