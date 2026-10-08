package server

import (
	"context"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// fakeDNSRecord is one canned answer record served by startFakeDNS.
type fakeDNSRecord struct {
	typ  dnsmessage.Type
	addr netip.Addr
	ttl  uint32
}

// startFakeDNS runs a local UDP DNS server answering every query for `name`
// from records (filtered by the queried type) and NXDOMAIN otherwise.
func startFakeDNS(t *testing.T, name string, records []fakeDNSRecord) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no local UDP: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			var p dnsmessage.Parser
			h, err := p.Start(buf[:n])
			if err != nil {
				continue
			}
			q, err := p.Question()
			if err != nil {
				continue
			}
			rh := dnsmessage.Header{ID: h.ID, Response: true, RecursionDesired: true}
			if q.Name.String() != name {
				rh.RCode = dnsmessage.RCodeNameError
			}
			b := dnsmessage.NewBuilder(nil, rh)
			_ = b.StartQuestions()
			_ = b.Question(q)
			_ = b.StartAnswers()
			if rh.RCode == dnsmessage.RCodeSuccess {
				for _, r := range records {
					if r.typ != q.Type {
						continue
					}
					hdr := dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: r.ttl}
					if r.typ == dnsmessage.TypeA {
						_ = b.AResource(hdr, dnsmessage.AResource{A: r.addr.As4()})
					} else {
						_ = b.AAAAResource(hdr, dnsmessage.AAAAResource{AAAA: r.addr.As16()})
					}
				}
			}
			out, _ := b.Finish()
			_, _ = pc.WriteTo(out, from)
		}
	}()
	return pc.LocalAddr().String()
}

func TestDNSTTLResolver_ReturnsBothFamiliesWithMinTTL(t *testing.T) {
	server := startFakeDNS(t, "api.example.", []fakeDNSRecord{
		{dnsmessage.TypeA, netip.MustParseAddr("192.0.2.1"), 42},
		{dnsmessage.TypeA, netip.MustParseAddr("192.0.2.2"), 90},
		{dnsmessage.TypeAAAA, netip.MustParseAddr("2001:db8::1"), 17},
	})
	r := &dnsTTLResolver{servers: []string{server}, timeout: 2 * time.Second}
	ans, err := r.LookupAddrsTTL(context.Background(), "api.example")
	if err != nil {
		t.Fatalf("LookupAddrsTTL: %v", err)
	}
	if got, want := addrStrings(ans.Addrs), []string{"192.0.2.1", "192.0.2.2", "2001:db8::1"}; !slices.Equal(got, want) {
		t.Fatalf("Addrs = %v, want %v", got, want)
	}
	if ans.TTL != 17*time.Second {
		t.Fatalf("TTL = %v, want the smallest record TTL 17s", ans.TTL)
	}
}

func TestDNSTTLResolver_NXDOMAINIsAnError(t *testing.T) {
	server := startFakeDNS(t, "api.example.", nil)
	r := &dnsTTLResolver{servers: []string{server}, timeout: 2 * time.Second}
	if _, err := r.LookupAddrsTTL(context.Background(), "missing.example"); err == nil {
		t.Fatal("NXDOMAIN must be an error so the resolver keeps the previous set")
	}
}

func TestResolvConfServers(t *testing.T) {
	p := filepath.Join(t.TempDir(), "resolv.conf")
	conf := "# comment\nsearch example.internal\nnameserver 127.0.0.53\nnameserver ::1\nnameserver not-an-ip\noptions edns0\n"
	if err := os.WriteFile(p, []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, want := resolvConfServers(p), []string{"127.0.0.53:53", "[::1]:53"}; !slices.Equal(got, want) {
		t.Fatalf("resolvConfServers = %v, want %v", got, want)
	}
	if got := resolvConfServers(filepath.Join(t.TempDir(), "absent")); len(got) != 0 {
		t.Fatalf("missing file should give no servers, got %v", got)
	}
}
