package sentinel

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/footprintai/containarium/internal/auth"
)

// #3119: /sentinel/peers has no request auth, so pool names (and the ?pool=
// filter, which lets a caller test names) are redacted for unsigned callers.
// A request carrying a valid daemon signature keeps the full response.

func peersCall(t *testing.T, m *Manager, query string, signWith string) (string, []testPeer) {
	t.Helper()
	req := httptest.NewRequest("GET", "/sentinel/peers"+query, nil)
	if signWith != "" {
		auth.SignSentinelRequest(req, []byte(signWith))
	}
	rec := httptest.NewRecorder()
	m.PeersHandler()(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var parsed struct {
		Peers []testPeer `json:"peers"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &parsed); err != nil {
		t.Fatal(err)
	}
	return rec.Body.String(), parsed.Peers
}

func TestPeersHandler_UnsignedSeesNoPool(t *testing.T) {
	m := newManagerForPeersTest(peersTestSecret)
	raw, peers := peersCall(t, m, "", "")
	if len(peers) != 2 {
		t.Fatalf("want 2 peers, got %d", len(peers))
	}
	if strings.Contains(raw, "pool") || strings.Contains(raw, "prod") {
		t.Fatalf("unsigned response leaks pool: %s", raw)
	}
}

func TestPeersHandler_UnsignedPoolQueryIgnored(t *testing.T) {
	m := newManagerForPeersTest(peersTestSecret)
	_, all := peersCall(t, m, "", "")
	for _, q := range []string{"?pool=prod", "?pool=ghost", "?pool="} {
		raw, got := peersCall(t, m, q, "")
		if len(got) != len(all) {
			t.Errorf("%s: filter honoured for unsigned caller (%d vs %d)", q, len(got), len(all))
		}
		if strings.Contains(raw, "pool") {
			t.Errorf("%s: leaks pool: %s", q, raw)
		}
	}
}

func TestPeersHandler_WrongSecretTreatedAsUnsigned(t *testing.T) {
	m := newManagerForPeersTest(peersTestSecret)
	raw, peers := peersCall(t, m, "?pool=prod", "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz")
	if len(peers) != 2 || strings.Contains(raw, "pool") {
		t.Fatalf("bad signature must be redacted: %s", raw)
	}
}

func TestPeersHandler_UnconfiguredSecretNeverTrustsSignature(t *testing.T) {
	m := newManagerForPeersTest("")
	raw, _ := peersCall(t, m, "", "") // no secret: nobody can be signed
	if strings.Contains(raw, "pool") {
		t.Fatalf("leaks pool: %s", raw)
	}
}

func TestPeersHandler_SignedSeesPoolAndFilter(t *testing.T) {
	m := newManagerForPeersTest(peersTestSecret)
	_, all := peersCall(t, m, "", peersTestSecret)
	if len(all) != 2 || all[0].Pool != "prod" {
		t.Fatalf("signed caller should see pool: %+v", all)
	}
	_, none := peersCall(t, m, "?pool=ghost", peersTestSecret)
	if len(none) != 0 {
		t.Fatalf("signed ?pool= filter must still work: %+v", none)
	}
}
