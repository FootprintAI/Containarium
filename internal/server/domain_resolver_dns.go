package server

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
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
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
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
	id := uint16(rand.Uint32())
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
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	if _, err := conn.Write(msg); err != nil {
		return nil, ttlUnknown, err
	}
	buf := make([]byte, 1232)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, ttlUnknown, err
	}

	var p dnsmessage.Parser
	h, err := p.Start(buf[:n])
	switch {
	case err != nil:
		return nil, ttlUnknown, err
	case h.ID != id || !h.Response:
		return nil, ttlUnknown, errors.New("dns: mismatched reply")
	case h.Truncated:
		return nil, ttlUnknown, errors.New("dns: truncated reply")
	case h.RCode != dnsmessage.RCodeSuccess:
		return nil, ttlUnknown, fmt.Errorf("dns: %s for %s", h.RCode, name)
	}
	if err := p.SkipAllQuestions(); err != nil {
		return nil, ttlUnknown, err
	}
	var addrs []netip.Addr
	ttl := ttlUnknown
	for {
		rh, err := p.AnswerHeader()
		if errors.Is(err, dnsmessage.ErrSectionDone) {
			break
		}
		if err != nil {
			return nil, ttlUnknown, err
		}
		// Every record in the chain (CNAMEs included) bounds the answer's life.
		if t := time.Duration(rh.TTL) * time.Second; ttl == ttlUnknown || t < ttl {
			ttl = t
		}
		switch rh.Type {
		case dnsmessage.TypeA:
			rr, err := p.AResource()
			if err != nil {
				return nil, ttlUnknown, err
			}
			addrs = append(addrs, netip.AddrFrom4(rr.A))
		case dnsmessage.TypeAAAA:
			rr, err := p.AAAAResource()
			if err != nil {
				return nil, ttlUnknown, err
			}
			addrs = append(addrs, netip.AddrFrom16(rr.AAAA))
		default:
			if err := p.SkipAnswer(); err != nil {
				return nil, ttlUnknown, err
			}
		}
	}
	return addrs, ttl, nil
}
