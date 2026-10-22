//go:build !containarium_client

package server

// mTLS transport tests for the CA-provider surface (#1415, option 1):
// the client-certificate CN IS the cluster identity. These dial the
// real listener with real minted certs — the exact handshake the
// stock CA binary performs.

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	clustercore "github.com/footprintai/containarium/pkg/core/cluster"
	capb "github.com/footprintai/containarium/pkg/pb/thirdparty/externalgrpc"
)

func mtlsRig(t *testing.T) (*ClusterPKI, string, *ClusterServer, *ClusterReconciler) {
	t.Helper()
	pki, err := LoadOrCreateClusterPKI(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	srv, rec, host := testReconcilerRig(t)
	mgr := clustercore.NewManagerWithLoader(host, func() ([]byte, error) { return []byte("k3s-bin"), nil })
	provider := NewCAProviderServer(srv.Store(), mgr)
	addr, stop, err := StartClusterCAListener("127.0.0.1:0", []string{"127.0.0.1"}, pki, provider)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(stop)
	return pki, addr, srv, rec
}

func dialWithCert(t *testing.T, pki *ClusterPKI, addr string, certPEM, keyPEM []byte) capb.CloudProviderClient {
	t.Helper()
	clientCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pki.CAPEM()) {
		t.Fatal("bad CA PEM")
	}
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      pool,
	})))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return capb.NewCloudProviderClient(conn)
}

func TestCAMTLS_CertCNIsTheIdentity(t *testing.T) {
	pki, addr, srv, _ := mtlsRig(t)
	mustCreate(t, srv, tenantCtx("alice"), "demo")

	cert, key, err := pki.MintClientCert("alice", "demo")
	if err != nil {
		t.Fatal(err)
	}
	client := dialWithCert(t, pki, addr, cert, key)

	// No bearer token, no metadata — the certificate is the identity.
	resp, err := client.NodeGroups(context.Background(), &capb.NodeGroupsRequest{})
	if err != nil {
		t.Fatalf("NodeGroups over mTLS: %v", err)
	}
	if len(resp.NodeGroups) != 3 || !strings.HasPrefix(resp.NodeGroups[0].Id, "alice/demo/") {
		t.Fatalf("groups over mTLS = %+v", resp.NodeGroups)
	}
}

func TestCAMTLS_WrongClusterCertIsRefused(t *testing.T) {
	pki, addr, srv, _ := mtlsRig(t)
	mustCreate(t, srv, tenantCtx("alice"), "demo")

	// A valid cert for a DIFFERENT cluster passes the handshake but
	// cannot touch demo's node groups.
	cert, key, err := pki.MintClientCert("alice", "other")
	if err != nil {
		t.Fatal(err)
	}
	client := dialWithCert(t, pki, addr, cert, key)
	_, err = client.NodeGroupTargetSize(context.Background(), &capb.NodeGroupTargetSizeRequest{Id: "alice/demo/small"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("wrong-cluster cert = %v, want PermissionDenied", err)
	}
}

func TestCAMTLS_ForeignCAFailsTheHandshake(t *testing.T) {
	pki, addr, srv, _ := mtlsRig(t)
	mustCreate(t, srv, tenantCtx("alice"), "demo")

	// A cert minted by a DIFFERENT authority (even with the right CN)
	// never reaches a handler — the handshake itself fails.
	foreign, err := LoadOrCreateClusterPKI(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cert, key, err := foreign.MintClientCert("alice", "demo")
	if err != nil {
		t.Fatal(err)
	}
	client := dialWithCert(t, pki, addr, cert, key)
	_, err = client.NodeGroups(context.Background(), &capb.NodeGroupsRequest{})
	if err == nil {
		t.Fatal("foreign-CA cert accepted")
	}
	if status.Code(err) == codes.PermissionDenied {
		t.Fatalf("foreign-CA cert reached a handler (%v); it must die in the handshake", err)
	}
}

func TestCAMTLS_PKIPersistsAcrossLoads(t *testing.T) {
	dir := t.TempDir()
	pki1, err := LoadOrCreateClusterPKI(dir)
	if err != nil {
		t.Fatal(err)
	}
	pki2, err := LoadOrCreateClusterPKI(dir)
	if err != nil {
		t.Fatal(err)
	}
	// Same CA on reload: certs minted before a daemon restart stay valid.
	if string(pki1.CAPEM()) != string(pki2.CAPEM()) {
		t.Fatal("cluster CA changed across loads — existing cluster credentials would all break on daemon restart")
	}
}

func TestReconciler_DeploysAutoscalerOntoCP(t *testing.T) {
	srv, rec, host := testReconcilerRig(t)
	rec.SetCADeployer("10.0.0.1:36442", func(owner, name string) (clustercore.CACredentials, error) {
		return clustercore.CACredentials{
			ClientCertPEM: []byte("CERT"), ClientKeyPEM: []byte("KEY"), CACertPEM: []byte("CA"),
		}, nil
	})
	mustCreate(t, srv, tenantCtx("alice"), "demo")
	ctx := context.Background()
	rec.ReconcileOnce(ctx)
	rec.ReconcileOnce(ctx)
	rec.ReconcileOnce(ctx)

	cp := "alice-k8s-demo-cp"
	if got := string(host.files[cp+":"+clustercore.CAClientKeyPath]); got != "KEY" {
		t.Fatalf("client key not deployed to the CP (got %q)", got)
	}
	cloudCfg := string(host.files[cp+":"+clustercore.CACloudConfigPath])
	if !strings.Contains(cloudCfg, `address: "10.0.0.1:36442"`) {
		t.Fatalf("cloud-config missing provider address:\n%s", cloudCfg)
	}
	unit := string(host.files[cp+":/root/containarium-ca-bootstrap.sh"])
	if !strings.Contains(unit, clustercore.CAImage) {
		t.Fatal("CA unit does not pin the image digest")
	}
}

// The scale-down timers travel reconciler -> DeployCA -> the unit on the
// CP. Unset, the unit carries no --scale-down-* flag (stock autoscaler).
func TestReconciler_CAScaleDownTimersReachTheUnit(t *testing.T) {
	for _, tc := range []struct {
		name            string
		delay, unneeded time.Duration
		want, wantNot   []string
	}{
		{name: "unset keeps the stock timers", wantNot: []string{"--scale-down-"}},
		{
			name: "set timers are rendered", delay: time.Minute, unneeded: time.Minute,
			want: []string{"--scale-down-delay-after-add=1m0s", "--scale-down-unneeded-time=1m0s"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, rec, host := testReconcilerRig(t)
			rec.SetCADeployer("10.0.0.1:36442", func(owner, name string) (clustercore.CACredentials, error) {
				return clustercore.CACredentials{ClientCertPEM: []byte("C"), ClientKeyPEM: []byte("K"), CACertPEM: []byte("A")}, nil
			})
			rec.SetCAScaleDown(tc.delay, tc.unneeded)
			mustCreate(t, srv, tenantCtx("alice"), "demo")
			ctx := context.Background()
			for i := 0; i < 3; i++ {
				rec.ReconcileOnce(ctx)
			}
			unit := string(host.files["alice-k8s-demo-cp:/root/containarium-ca-bootstrap.sh"])
			if unit == "" {
				t.Fatal("no CA unit deployed")
			}
			for _, s := range tc.want {
				if !strings.Contains(unit, s) {
					t.Errorf("unit missing %q:\n%s", s, unit)
				}
			}
			for _, s := range tc.wantNot {
				if strings.Contains(unit, s) {
					t.Errorf("unit must not contain %q:\n%s", s, unit)
				}
			}
		})
	}
}

func TestParseCAScaleDownEnv(t *testing.T) {
	const (
		delayKey    = "CONTAINARIUM_CLUSTER_CA_SCALE_DOWN_DELAY_AFTER_ADD"
		unneededKey = "CONTAINARIUM_CLUSTER_CA_SCALE_DOWN_UNNEEDED_TIME"
	)
	for _, tc := range []struct {
		name                    string
		env                     map[string]string
		wantDelay, wantUnneeded time.Duration
		wantErr                 bool
	}{
		{name: "unset", env: map[string]string{}},
		{name: "both", env: map[string]string{delayKey: "1m", unneededKey: "90s"}, wantDelay: time.Minute, wantUnneeded: 90 * time.Second},
		{name: "one", env: map[string]string{unneededKey: "2m"}, wantUnneeded: 2 * time.Minute},
		{name: "not a duration", env: map[string]string{delayKey: "soon"}, wantErr: true},
		{name: "zero is not an override", env: map[string]string{delayKey: "0s"}, wantErr: true},
		{name: "negative", env: map[string]string{unneededKey: "-1m"}, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			delay, unneeded, err := parseCAScaleDownEnv(func(k string) string { return tc.env[k] })
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if err == nil && (delay != tc.wantDelay || unneeded != tc.wantUnneeded) {
				t.Fatalf("got (%v, %v), want (%v, %v)", delay, unneeded, tc.wantDelay, tc.wantUnneeded)
			}
		})
	}
}
