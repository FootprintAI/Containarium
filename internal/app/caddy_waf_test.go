package app

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCaddyWAFHandler_JSON(t *testing.T) {
	h := CaddyWAFHandler{Handler: "waf", Directives: "SecRuleEngine On"}
	if h.HandlerName() != "waf" {
		t.Fatalf("HandlerName = %q, want waf", h.HandlerName())
	}
	b, err := json.Marshal(h)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got := string(b)
	if !strings.Contains(got, `"handler":"waf"`) || !strings.Contains(got, `"directives":"SecRuleEngine On"`) {
		t.Fatalf("WAF handler JSON wrong: %s", got)
	}
}

func TestDefaultWAFDirectives(t *testing.T) {
	on := DefaultWAFDirectives(true)
	if !strings.Contains(on, "SecRuleEngine On") {
		t.Errorf("enforce should set SecRuleEngine On: %q", on)
	}
	off := DefaultWAFDirectives(false)
	if !strings.Contains(off, "SecRuleEngine DetectionOnly") {
		t.Errorf("non-enforce should set DetectionOnly: %q", off)
	}
	// Both load the CRS.
	for _, d := range []string{on, off} {
		if !strings.Contains(d, "@owasp_crs") || !strings.Contains(d, "@coraza.conf-recommended") {
			t.Errorf("directives should include the CRS + coraza baseline: %q", d)
		}
	}
}

func TestPrependWAF(t *testing.T) {
	rp := CaddyReverseProxyHandler{Handler: "reverse_proxy"}
	base := []CaddyHandler{rp}

	// Disabled → unchanged slice (byte-identical routes when WAF is off).
	if got := PrependWAF(base, false, "x"); len(got) != 1 || got[0].HandlerName() != "reverse_proxy" {
		t.Fatalf("disabled PrependWAF changed the chain: %+v", got)
	}

	// Enabled → WAF first, then reverse_proxy (inspect before forward).
	got := PrependWAF(base, true, "SecRuleEngine On")
	if len(got) != 2 || got[0].HandlerName() != "waf" || got[1].HandlerName() != "reverse_proxy" {
		t.Fatalf("enabled PrependWAF order wrong: %+v", got)
	}
	if w, ok := got[0].(CaddyWAFHandler); !ok || w.Directives != "SecRuleEngine On" {
		t.Fatalf("WAF handler not carrying directives: %+v", got[0])
	}
}

// TestAddRoute_WAFDisabledByteIdentical guards that with WAF off, a programmed
// route's JSON is exactly what it was before this change — i.e. the []CaddyHandler
// switch is invisible to live ingress.
func TestAddRoute_WAFDisabledByteIdentical(t *testing.T) {
	handler := CaddyReverseProxyHandler{
		Handler:   "reverse_proxy",
		Upstreams: []CaddyUpstreamTyped{{Dial: "10.0.0.5:8080"}},
	}
	// WAF off → single reverse_proxy handler.
	route := caddyRouteJSON{
		ID:     "alice",
		Match:  []CaddyMatchTyped{{Host: []string{"alice.example.com"}}},
		Handle: PrependWAF([]CaddyHandler{handler}, false, ""),
	}
	b, _ := json.Marshal(route)
	got := string(b)
	if strings.Contains(got, `"waf"`) {
		t.Fatalf("WAF-disabled route should carry no waf handler: %s", got)
	}
	if !strings.Contains(got, `"handler":"reverse_proxy"`) || !strings.Contains(got, `10.0.0.5:8080`) {
		t.Fatalf("reverse_proxy route malformed: %s", got)
	}

	// WAF on → waf handler appears before reverse_proxy.
	route.Handle = PrependWAF([]CaddyHandler{handler}, true, DefaultWAFDirectives(true))
	b2, _ := json.Marshal(route)
	got2 := string(b2)
	wafIdx := strings.Index(got2, `"handler":"waf"`)
	rpIdx := strings.Index(got2, `"handler":"reverse_proxy"`)
	if wafIdx < 0 || rpIdx < 0 || wafIdx > rpIdx {
		t.Fatalf("WAF handler should precede reverse_proxy in JSON: %s", got2)
	}
}

func TestProxyManager_WithWAF(t *testing.T) {
	pm := NewProxyManager("http://127.0.0.1:2019", "example.com")
	if pm.WAFEnabled() {
		t.Fatal("WAF should be off by default")
	}
	pm.WithWAF(DefaultWAFDirectives(false))
	if !pm.WAFEnabled() {
		t.Fatal("WithWAF should enable it")
	}
}
