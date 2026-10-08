package server

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// fakeRR is one canned answer record. Owner "" means the queried name.
type fakeRR struct {
	owner  string
	typ    dnsmessage.Type
	addr   netip.Addr // A / AAAA
	target string     // CNAME
	ttl    uint32
}

// fakeReply shapes one reply packet. Zero value = a correct reply.
type fakeReply struct {
	answers   []fakeRR
	idDelta   uint16 // non-zero: reply with the wrong ID
	question  string // non-empty: echo this name instead of the queried one
	truncated bool
	rcode     dnsmessage.RCode
}

// startDNSServer runs a local UDP DNS server; respond maps each query to the
// reply packets to send, in order.
func startDNSServer(t *testing.T, respond func(q dnsmessage.Question) []fakeReply) string {
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
			for _, r := range respond(q) {
				_, _ = pc.WriteTo(buildFakeReply(t, h.ID, q, r), from)
			}
		}
	}()
	return pc.LocalAddr().String()
}

func buildFakeReply(t *testing.T, id uint16, q dnsmessage.Question, r fakeReply) []byte {
	echo := q
	if r.question != "" {
		echo.Name = dnsmessage.MustNewName(r.question)
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id + r.idDelta, Response: true, Truncated: r.truncated, RCode: r.rcode})
	_ = b.StartQuestions()
	_ = b.Question(echo)
	_ = b.StartAnswers()
	for _, rr := range r.answers {
		owner := q.Name
		if rr.owner != "" {
			owner = dnsmessage.MustNewName(rr.owner)
		}
		hdr := dnsmessage.ResourceHeader{Name: owner, Class: dnsmessage.ClassINET, TTL: rr.ttl}
		var err error
		switch rr.typ {
		case dnsmessage.TypeA:
			err = b.AResource(hdr, dnsmessage.AResource{A: rr.addr.As4()})
		case dnsmessage.TypeAAAA:
			err = b.AAAAResource(hdr, dnsmessage.AAAAResource{AAAA: rr.addr.As16()})
		case dnsmessage.TypeCNAME:
			err = b.CNAMEResource(hdr, dnsmessage.CNAMEResource{CNAME: dnsmessage.MustNewName(rr.target)})
		}
		if err != nil {
			t.Errorf("build reply: %v", err)
		}
	}
	out, err := b.Finish()
	if err != nil {
		t.Errorf("finish reply: %v", err)
	}
	return out
}

// byType answers each query with the records of its type (CNAMEs always).
func byType(answers ...fakeRR) func(q dnsmessage.Question) []fakeReply {
	return func(q dnsmessage.Question) []fakeReply {
		var out []fakeRR
		for _, a := range answers {
			if a.typ == q.Type || a.typ == dnsmessage.TypeCNAME {
				out = append(out, a)
			}
		}
		return []fakeReply{{answers: out}}
	}
}

func ip(s string) netip.Addr { return netip.MustParseAddr(s) }

func lookupVia(t *testing.T, server string, timeout time.Duration) (dnsAnswer, error) {
	t.Helper()
	r := &dnsTTLResolver{servers: []string{server}, timeout: timeout}
	return r.LookupAddrsTTL(context.Background(), "api.example")
}

func TestDNSTTLResolver_ReturnsBothFamiliesWithMinTTL(t *testing.T) {
	server := startDNSServer(t, byType(
		fakeRR{typ: dnsmessage.TypeA, addr: ip("192.0.2.1"), ttl: 42},
		fakeRR{typ: dnsmessage.TypeA, addr: ip("192.0.2.2"), ttl: 90},
		fakeRR{typ: dnsmessage.TypeAAAA, addr: ip("2001:db8::1"), ttl: 17},
	))
	ans, err := lookupVia(t, server, 2*time.Second)
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

func TestDNSTTLResolver_OffNameRecordsIgnored(t *testing.T) {
	server := startDNSServer(t, byType(
		fakeRR{typ: dnsmessage.TypeA, addr: ip("192.0.2.1"), ttl: 60},
		fakeRR{owner: "evil.example.", typ: dnsmessage.TypeA, addr: ip("198.51.100.66"), ttl: 5},
	))
	ans, err := lookupVia(t, server, 2*time.Second)
	if err != nil {
		t.Fatalf("LookupAddrsTTL: %v", err)
	}
	if got := addrStrings(ans.Addrs); !slices.Equal(got, []string{"192.0.2.1"}) {
		t.Fatalf("Addrs = %v, the off-name record must not be accepted", got)
	}
	if ans.TTL != 60*time.Second {
		t.Fatalf("TTL = %v, want 60s (the off-name record's TTL must not count)", ans.TTL)
	}

	// A reply holding only off-name records yields no address at all.
	server = startDNSServer(t, byType(fakeRR{owner: "evil.example.", typ: dnsmessage.TypeA, addr: ip("198.51.100.66"), ttl: 5}))
	if ans, err := lookupVia(t, server, 2*time.Second); err == nil {
		t.Fatalf("only off-name records must be an error, got %+v", ans)
	}
}

func TestDNSTTLResolver_CNAMEChain(t *testing.T) {
	server := startDNSServer(t, byType(
		fakeRR{typ: dnsmessage.TypeCNAME, target: "edge.cdn.example.", ttl: 300},
		fakeRR{owner: "edge.cdn.example.", typ: dnsmessage.TypeCNAME, target: "node.cdn.example.", ttl: 120},
		fakeRR{owner: "node.cdn.example.", typ: dnsmessage.TypeA, addr: ip("192.0.2.9"), ttl: 45},
		fakeRR{owner: "unrelated.example.", typ: dnsmessage.TypeA, addr: ip("198.51.100.7"), ttl: 3},
	))
	ans, err := lookupVia(t, server, 2*time.Second)
	if err != nil {
		t.Fatalf("LookupAddrsTTL: %v", err)
	}
	if got := addrStrings(ans.Addrs); !slices.Equal(got, []string{"192.0.2.9"}) {
		t.Fatalf("Addrs = %v, want only the chain's [192.0.2.9]", got)
	}
	if ans.TTL != 45*time.Second {
		t.Fatalf("TTL = %v, want 45s (min over the chain only)", ans.TTL)
	}

	// The chain's CNAME TTL bounds the answer when it is the smallest.
	server = startDNSServer(t, byType(
		fakeRR{typ: dnsmessage.TypeCNAME, target: "edge.cdn.example.", ttl: 10},
		fakeRR{owner: "edge.cdn.example.", typ: dnsmessage.TypeA, addr: ip("192.0.2.9"), ttl: 45},
	))
	if ans, err := lookupVia(t, server, 2*time.Second); err != nil || ans.TTL != 10*time.Second {
		t.Fatalf("got %+v, %v; want TTL 10s from the CNAME", ans, err)
	}
}

func TestDNSTTLResolver_CNAMELoopIsAnError(t *testing.T) {
	server := startDNSServer(t, byType(
		fakeRR{typ: dnsmessage.TypeCNAME, target: "b.example.", ttl: 60},
		fakeRR{owner: "b.example.", typ: dnsmessage.TypeCNAME, target: "api.example.", ttl: 60},
	))
	if ans, err := lookupVia(t, server, 2*time.Second); err == nil {
		t.Fatalf("a CNAME loop must be an error, got %+v", ans)
	}
}

func TestDNSTTLResolver_RejectedReplies(t *testing.T) {
	good := []fakeRR{{typ: dnsmessage.TypeA, addr: ip("192.0.2.1"), ttl: 60}}
	cases := map[string]fakeReply{
		"mismatched question": {answers: good, question: "evil.example."},
		"truncated":           {answers: good, truncated: true},
		"mismatched id":       {answers: good, idDelta: 1},
		"NXDOMAIN":            {rcode: dnsmessage.RCodeNameError},
	}
	for name, reply := range cases {
		t.Run(name, func(t *testing.T) {
			server := startDNSServer(t, func(dnsmessage.Question) []fakeReply { return []fakeReply{reply} })
			if ans, err := lookupVia(t, server, 300*time.Millisecond); err == nil {
				t.Fatalf("reply must be rejected, got %+v", ans)
			}
		})
	}
}

func TestDNSTTLResolver_StrayPacketThenReply(t *testing.T) {
	server := startDNSServer(t, func(q dnsmessage.Question) []fakeReply {
		var rr []fakeRR
		if q.Type == dnsmessage.TypeA {
			rr = []fakeRR{{typ: dnsmessage.TypeA, addr: ip("192.0.2.1"), ttl: 60}}
		}
		// A spoofed/stale packet with the wrong ID arrives first.
		bad := []fakeRR{{typ: dnsmessage.TypeA, addr: ip("198.51.100.66"), ttl: 60}}
		return []fakeReply{{answers: bad, idDelta: 1}, {answers: rr}}
	})
	ans, err := lookupVia(t, server, 2*time.Second)
	if err != nil {
		t.Fatalf("LookupAddrsTTL: %v", err)
	}
	if got := addrStrings(ans.Addrs); !slices.Equal(got, []string{"192.0.2.1"}) {
		t.Fatalf("Addrs = %v, want the matching reply only", got)
	}
}

func TestFallbackTTLResolver(t *testing.T) {
	primary := &fakeTTLResolver{answers: map[string]dnsAnswer{"a.example": {Addrs: addrs("192.0.2.1"), TTL: 20 * time.Second}}}
	fallback := &fakeTTLResolver{answers: map[string]dnsAnswer{
		"a.example": {Addrs: addrs("192.0.2.99"), TTL: ttlUnknown},
		"b.example": {Addrs: addrs("192.0.2.2"), TTL: ttlUnknown},
	}}
	primary.errs = map[string]error{"b.example": errors.New("truncated")}
	r := fallbackTTLResolver{primary: primary, fallback: fallback}

	ans, err := r.LookupAddrsTTL(context.Background(), "a.example")
	if err != nil || ans.TTL != 20*time.Second || fallback.calls["a.example"] != 0 {
		t.Fatalf("primary success must not use the fallback: %+v %v calls=%v", ans, err, fallback.calls)
	}
	ans, err = r.LookupAddrsTTL(context.Background(), "b.example")
	if err != nil || ans.TTL != ttlUnknown || addrStrings(ans.Addrs)[0] != "192.0.2.2" {
		t.Fatalf("primary error must fall back to the stdlib path: %+v %v", ans, err)
	}
	fallback.errs = map[string]error{"b.example": errors.New("nxdomain")}
	if _, err := r.LookupAddrsTTL(context.Background(), "b.example"); err == nil {
		t.Fatal("both failing must be an error")
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
