package server

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// dnsTTLResolver is the TTL-aware lookup path (#2379): net.Resolver exposes no
// record TTLs, so this sends A and AAAA queries itself (UDP, EDNS0) to the
// system's configured nameservers and reports the smallest answer TTL.
// Names are queried as absolute (no search-list expansion): egress_domains are
// FQDNs. A truncated reply is an error, so the caller falls back to the stdlib
// resolver (which retries over TCP) with the TTL unknown.
type dnsTTLResolver struct {
	servers []string // host:port, tried in order
	timeout time.Duration
}

// fallbackTTLResolver tries primary, then fallback on any error.
type fallbackTTLResolver struct {
	primary, fallback addrTTLResolver
}

func (f fallbackTTLResolver) LookupAddrsTTL(ctx context.Context, host string) (dnsAnswer, error) {
	if ans, err := f.primary.LookupAddrsTTL(ctx, host); err == nil {
		return ans, nil
	}
	return f.fallback.LookupAddrsTTL(ctx, host)
}

// newSystemTTLResolver is the production resolver: raw DNS against
// /etc/resolv.conf's nameservers, falling back to net.DefaultResolver (TTL
// unknown → the 60s cap, today's behaviour) when that path fails or no
// nameserver is configured.
func newSystemTTLResolver() addrTTLResolver {
	std := stdlibTTLResolver{r: net.DefaultResolver}
	servers := resolvConfServers("/etc/resolv.conf")
	if len(servers) == 0 {
		return std
	}
	return fallbackTTLResolver{primary: &dnsTTLResolver{servers: servers, timeout: 5 * time.Second}, fallback: std}
}

// resolvConfServers returns the "nameserver" entries of a resolv.conf as
// host:port (port 53). Unparseable entries are skipped; a missing file is none.
func resolvConfServers(path string) []string {
	f, err := os.Open(path) // #nosec G304 -- /etc/resolv.conf in production; a temp file in tests
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 || fields[0] != "nameserver" {
			continue
		}
		if ip, err := netip.ParseAddr(fields[1]); err == nil {
			out = append(out, net.JoinHostPort(ip.String(), "53"))
		}
	}
	return out
}

func (r *dnsTTLResolver) LookupAddrsTTL(ctx context.Context, host string) (dnsAnswer, error) {
	if !strings.HasSuffix(host, ".") {
		host += "."
	}
	name, err := dnsmessage.NewName(host)
	if err != nil {
		return dnsAnswer{}, err
	}
	out := dnsAnswer{TTL: ttlUnknown}
	for _, qtype := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA} {
		addrs, ttl, err := r.queryAny(ctx, name, qtype)
		if err != nil {
			return dnsAnswer{}, err
		}
		out.Addrs = append(out.Addrs, addrs...)
		if ttl != ttlUnknown && (out.TTL == ttlUnknown || ttl < out.TTL) {
			out.TTL = ttl
		}
	}
	if len(out.Addrs) == 0 {
		return dnsAnswer{}, fmt.Errorf("dns: no A/AAAA records for %s", host)
	}
	return out, nil
}

// queryAny asks each server in turn until one answers.
func (r *dnsTTLResolver) queryAny(ctx context.Context, name dnsmessage.Name, qtype dnsmessage.Type) ([]netip.Addr, time.Duration, error) {
	err := errors.New("dns: no nameservers")
	for _, s := range r.servers {
		var addrs []netip.Addr
		var ttl time.Duration
		if addrs, ttl, err = r.query(ctx, s, name, qtype); err == nil {
			return addrs, ttl, nil
		}
	}
	return nil, ttlUnknown, err
}

func (r *dnsTTLResolver) query(ctx context.Context, server string, name dnsmessage.Name, qtype dnsmessage.Type) ([]netip.Addr, time.Duration, error) {
	// An unpredictable query ID is part of the defence against spoofed replies.
	var idb [2]byte
	if _, err := rand.Read(idb[:]); err != nil {
		return nil, ttlUnknown, err
	}
	id := binary.BigEndian.Uint16(idb[:])
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id, RecursionDesired: true})
	b.EnableCompression()
	_ = b.StartQuestions()
	_ = b.Question(dnsmessage.Question{Name: name, Type: qtype, Class: dnsmessage.ClassINET})
	_ = b.StartAdditionals()
	var opt dnsmessage.ResourceHeader
	_ = opt.SetEDNS0(1232, dnsmessage.RCodeSuccess, false)
	_ = b.OPTResource(opt, dnsmessage.OPTResource{})
	msg, err := b.Finish()
	if err != nil {
		return nil, ttlUnknown, err
	}

	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, "udp", server)
	if err != nil {
		return nil, ttlUnknown, err
	}
	defer func() { _ = conn.Close() }()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	if _, err := conn.Write(msg); err != nil {
		return nil, ttlUnknown, err
	}
	buf := make([]byte, 1232)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return nil, ttlUnknown, err // includes the deadline: no matching reply in time
		}
		addrs, ttl, err := parseDNSReply(buf[:n], id, name, qtype)
		if errors.Is(err, errStrayReply) {
			continue // not a reply to this query: keep waiting until the deadline
		}
		return addrs, ttl, err
	}
}

// errStrayReply marks a packet that is not a reply to our query (wrong ID).
var errStrayReply = errors.New("dns: reply id does not match the query")

// maxCNAMEChain bounds how many CNAME hops are followed (and breaks loops).
const maxCNAMEChain = 8

// dnsRecord is one parsed answer record of a type the chain walk uses.
type dnsRecord struct {
	owner  string // lower-case FQDN
	typ    dnsmessage.Type
	ttl    time.Duration
	addr   netip.Addr // A / AAAA
	target string     // CNAME, lower-case FQDN
}

// parseDNSReply validates a reply against the query (ID, single echoed
// question = name/type/class) and returns the qtype addresses on the queried
// name's CNAME chain, with the smallest TTL over that chain only. Records for
// any other owner name are ignored, so an off-name record cannot reach an
// allow-list.
func parseDNSReply(msg []byte, id uint16, name dnsmessage.Name, qtype dnsmessage.Type) ([]netip.Addr, time.Duration, error) {
	var p dnsmessage.Parser
	h, err := p.Start(msg)
	switch {
	case err != nil:
		return nil, ttlUnknown, err
	case h.ID != id || !h.Response:
		return nil, ttlUnknown, errStrayReply
	case h.Truncated:
		return nil, ttlUnknown, errors.New("dns: truncated reply")
	case h.RCode != dnsmessage.RCodeSuccess:
		return nil, ttlUnknown, fmt.Errorf("dns: %s for %s", h.RCode, name)
	}
	qs, err := p.AllQuestions()
	if err != nil {
		return nil, ttlUnknown, err
	}
	if len(qs) != 1 || !strings.EqualFold(qs[0].Name.String(), name.String()) || qs[0].Type != qtype || qs[0].Class != dnsmessage.ClassINET {
		return nil, ttlUnknown, errors.New("dns: reply question does not match the query")
	}
	var recs []dnsRecord
	for {
		rh, err := p.AnswerHeader()
		if errors.Is(err, dnsmessage.ErrSectionDone) {
			break
		}
		if err != nil {
			return nil, ttlUnknown, err
		}
		rec := dnsRecord{owner: strings.ToLower(rh.Name.String()), typ: rh.Type, ttl: time.Duration(rh.TTL) * time.Second}
		switch rh.Type {
		case dnsmessage.TypeA:
			rr, err := p.AResource()
			if err != nil {
				return nil, ttlUnknown, err
			}
			rec.addr = netip.AddrFrom4(rr.A)
		case dnsmessage.TypeAAAA:
			rr, err := p.AAAAResource()
			if err != nil {
				return nil, ttlUnknown, err
			}
			rec.addr = netip.AddrFrom16(rr.AAAA)
		case dnsmessage.TypeCNAME:
			rr, err := p.CNAMEResource()
			if err != nil {
				return nil, ttlUnknown, err
			}
			rec.target = strings.ToLower(rr.CNAME.String())
		default:
			if err := p.SkipAnswer(); err != nil {
				return nil, ttlUnknown, err
			}
			continue
		}
		recs = append(recs, rec)
	}
	return followCNAMEChain(recs, strings.ToLower(name.String()), qtype)
}

// followCNAMEChain walks from the queried name through CNAMEs, returning the
// qtype records owned by the first chain name that has any. The TTL is the
// minimum over the CNAMEs walked and those records; no address → ttlUnknown.
func followCNAMEChain(recs []dnsRecord, owner string, qtype dnsmessage.Type) ([]netip.Addr, time.Duration, error) {
	chainTTL := ttlUnknown
	lower := func(cur, t time.Duration) time.Duration {
		if cur == ttlUnknown || t < cur {
			return t
		}
		return cur
	}
	for hop := 0; ; hop++ {
		var addrs []netip.Addr
		ttl := chainTTL
		var cname *dnsRecord
		for i := range recs {
			switch r := &recs[i]; {
			case r.owner != owner:
				// off-chain record: ignored
			case r.typ == qtype:
				addrs = append(addrs, r.addr)
				ttl = lower(ttl, r.ttl)
			case r.typ == dnsmessage.TypeCNAME:
				cname = r
			}
		}
		switch {
		case len(addrs) > 0:
			return addrs, ttl, nil
		case cname == nil:
			return nil, ttlUnknown, nil
		case hop >= maxCNAMEChain:
			return nil, ttlUnknown, errors.New("dns: CNAME chain too long or looping")
		}
		chainTTL = lower(chainTTL, cname.ttl)
		owner = cname.target
	}
}
