package mcp

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTenantReviewMalformedSourceListsMustNeverSubmitPartialPatch(t *testing.T) {
	for _, bad := range []interface{}{"team-old", []interface{}{"team-old", 17}, []interface{}{17}} {
		posts := 0
		f := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			posts++
			w.Write([]byte(`{"applicationState":"TENANT_ACCESS_APPLICATION_STATE_PENDING"}`))
		}))
		api := NewClient(f.URL, "fixture")
		args := map[string]interface{}{"changes": []interface{}{map[string]interface{}{"destination": "team-a", "expected_revision": "absent", "add_sources": []interface{}{"team-b"}, "remove_sources": bad}}}
		_, err := tenantNetworkHandler("patch")(api, args)
		f.Close()
		if err == nil || posts != 0 {
			t.Errorf("malformed removal %v submitted partial patch: posts=%d err=%v", bad, posts, err)
		}
	}
}
