// tier2-l4-lifecycle: drives a real caddy-l4 server through the operations
// the daemon performs at runtime (EnableL4ProxyProtocol → ActivateL4 →
// AddL4Route * N → RemoveL4Route → ListL4Routes) and asserts the pattern B
// wrapping is intact at every step. This is the regression test for the
// prod-broke-everything bug from attempt 3, where RouteSyncJob's CRUD
// undid the wrapping within seconds of daemon startup.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/footprintai/containarium/internal/app"
)

func main() {
	adminURL := flag.String("admin", "http://127.0.0.1:2019", "Caddy admin URL")
	trusted := flag.String("trusted", "127.0.0.0/8", "comma-separated trusted CIDRs")
	flag.Parse()

	cidrs := strings.Split(*trusted, ",")
	m := app.NewL4ProxyManager(*adminURL)

	log.Println("step 1: EnableL4ProxyProtocol (records trusted CIDRs)")
	if err := m.EnableL4ProxyProtocol(cidrs); err != nil {
		log.Fatalf("EnableL4ProxyProtocol: %v", err)
	}

	log.Println("step 2: ActivateL4 (must produce wrapped shape)")
	if err := m.ActivateL4(); err != nil {
		log.Fatalf("ActivateL4: %v", err)
	}
	if err := assertWrappedAndCatchallV2(*adminURL, "after-activate"); err != nil {
		log.Fatalf("FAIL: %v", err)
	}

	log.Println("step 3: simulate 3 RouteSyncJob cycles of AddL4Route")
	for cycle := 0; cycle < 3; cycle++ {
		if err := m.AddL4Route("passthrough-a.example", "203.0.113.1", 50051); err != nil {
			log.Fatalf("cycle %d AddL4Route grpc: %v", cycle, err)
		}
		if err := m.AddL4Route("passthrough-b.example", "203.0.113.2", 50052); err != nil {
			log.Fatalf("cycle %d AddL4Route grpc-dev: %v", cycle, err)
		}
		if err := assertWrappedAndCatchallV2(*adminURL, fmt.Sprintf("after-add-cycle-%d", cycle)); err != nil {
			log.Fatalf("FAIL: %v", err)
		}
	}

	log.Println("step 4: RemoveL4Route (must keep wrapping)")
	if err := m.RemoveL4Route("passthrough-b.example"); err != nil {
		log.Fatalf("RemoveL4Route: %v", err)
	}
	if err := assertWrappedAndCatchallV2(*adminURL, "after-remove"); err != nil {
		log.Fatalf("FAIL: %v", err)
	}

	log.Println("step 5: ListL4Routes (must see the surviving SNI route)")
	routes, err := m.ListL4Routes()
	if err != nil {
		log.Fatalf("ListL4Routes: %v", err)
	}
	if len(routes) != 1 || routes[0].SNI != "passthrough-a.example" {
		log.Fatalf("FAIL: ListL4Routes = %v, want 1 entry for passthrough-a.example", routes)
	}

	log.Println("step 6: print full L4 server config")
	resp, err := http.Get(*adminURL + "/config/apps/layer4/servers/tls_passthrough")
	if err != nil {
		log.Fatalf("get layer4 config: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var pretty map[string]interface{}
	_ = json.Unmarshal(body, &pretty)
	out, _ := json.MarshalIndent(pretty, "", "  ")
	fmt.Println(string(out))

	log.Println("PASS: lifecycle complete, wrapping survived all 6 steps")
}

func assertWrappedAndCatchallV2(adminURL, label string) error {
	resp, err := http.Get(adminURL + "/config/apps/layer4/servers/tls_passthrough")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var srv map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&srv); err != nil {
		return err
	}
	outer, _ := srv["routes"].([]interface{})
	if len(outer) != 1 {
		return fmt.Errorf("[%s] expected 1 outer route (wrapped), got %d", label, len(outer))
	}
	hs, _ := outer[0].(map[string]interface{})["handle"].([]interface{})
	if len(hs) != 2 {
		return fmt.Errorf("[%s] expected 2 outer handlers, got %d", label, len(hs))
	}
	if hs[0].(map[string]interface{})["handler"] != "proxy_protocol" {
		return fmt.Errorf("[%s] outer handler[0] must be proxy_protocol, got %v", label, hs[0])
	}
	inner, _ := hs[1].(map[string]interface{})["routes"].([]interface{})
	if len(inner) == 0 {
		return fmt.Errorf("[%s] inner subroute has no routes", label)
	}
	last := inner[len(inner)-1].(map[string]interface{})
	if _, hasMatch := last["match"]; hasMatch {
		return fmt.Errorf("[%s] last inner route has a match clause — catchall is missing/displaced", label)
	}
	lastH := last["handle"].([]interface{})[0].(map[string]interface{})
	if lastH["proxy_protocol"] != "v2" {
		return fmt.Errorf("[%s] catchall proxy_protocol = %v, want v2", label, lastH["proxy_protocol"])
	}
	return nil
}
