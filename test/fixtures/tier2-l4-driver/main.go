// tier2-l4-driver: invokes app.L4ProxyManager.EnableL4ProxyProtocol against
// a real Caddy admin endpoint and asserts the resulting config matches the
// verified-good pattern B shape from sandbox tier 1. Cross-compiled and
// shipped to the sandbox to validate the daemon's actual code path produces
// the right Caddy config — no mocks, no fake admin, just the real binary
// against the real Caddy.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/footprintai/containarium/internal/app"
)

func main() {
	adminURL := flag.String("admin", "http://127.0.0.1:2019", "Caddy admin URL")
	trusted := flag.String("trusted", "127.0.0.0/8", "comma-separated trusted sender CIDRs")
	flag.Parse()

	cidrs := strings.Split(*trusted, ",")
	m := app.NewL4ProxyManager(*adminURL)
	if err := m.EnableL4ProxyProtocol(cidrs); err != nil {
		log.Fatalf("EnableL4ProxyProtocol: %v", err)
	}
	log.Printf("EnableL4ProxyProtocol returned no error; verifying stored config…")

	// Read back the L4 server config and check pattern B invariants.
	resp, err := http.Get(*adminURL + "/config/apps/layer4/servers/tls_passthrough")
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var srv map[string]interface{}
	if err := json.Unmarshal(body, &srv); err != nil {
		log.Fatalf("decode srv: %v\n%s", err, body)
	}

	pretty, _ := json.MarshalIndent(srv, "", "  ")
	fmt.Println(string(pretty))

	if err := assertPatternB(srv); err != nil {
		log.Fatalf("FAIL: %v", err)
	}
	log.Println("PASS: pattern B invariants hold")
}

func assertPatternB(srv map[string]interface{}) error {
	if _, has := srv["listener_wrappers"]; has {
		return fmt.Errorf("server-level listener_wrappers must NOT appear (caddy-l4 rejects)")
	}
	routes, _ := srv["routes"].([]interface{})
	if len(routes) != 1 {
		return fmt.Errorf("expected exactly 1 outer route, got %d", len(routes))
	}
	outer, _ := routes[0].(map[string]interface{})
	hs, _ := outer["handle"].([]interface{})
	if len(hs) != 2 {
		return fmt.Errorf("outer route must have 2 handlers, got %d", len(hs))
	}
	pp, _ := hs[0].(map[string]interface{})
	if pp["handler"] != "proxy_protocol" {
		return fmt.Errorf("first handler = %v, want proxy_protocol", pp["handler"])
	}
	if pp["timeout"] == nil {
		return fmt.Errorf("proxy_protocol handler missing timeout")
	}
	sub, _ := hs[1].(map[string]interface{})
	if sub["handler"] != "subroute" {
		return fmt.Errorf("second handler = %v, want subroute", sub["handler"])
	}
	inner, _ := sub["routes"].([]interface{})
	if len(inner) == 0 {
		return fmt.Errorf("subroute has no inner routes — existing routes were dropped")
	}
	// Walk inner routes, ensure catchall has proxy_protocol: v2 and SNI routes don't.
	for i, r := range inner {
		route, _ := r.(map[string]interface{})
		_, hasMatch := route["match"]
		handlers, _ := route["handle"].([]interface{})
		if len(handlers) == 0 {
			return fmt.Errorf("inner[%d] has no handlers", i)
		}
		first, _ := handlers[0].(map[string]interface{})
		if first["handler"] != "proxy" {
			continue // could be a different handler shape, skip
		}
		if hasMatch {
			if pp, has := first["proxy_protocol"]; has {
				return fmt.Errorf("inner[%d] (SNI route) MUST NOT have proxy_protocol; got %v", i, pp)
			}
		} else {
			if first["proxy_protocol"] != "v2" {
				return fmt.Errorf("inner[%d] (catchall) proxy_protocol = %v, want v2", i, first["proxy_protocol"])
			}
		}
	}

	if _, err := os.Stat("/dev/null"); err != nil {
		return fmt.Errorf("sanity check failed: %w", err)
	}
	return nil
}
