//go:build !windows && !containarium_client

package cmd

import (
	"bytes"
	"testing"

	"github.com/footprintai/containarium/internal/audit"
)

// `audit query` prints the tenant-supplied username and resource id (#3453).
func TestPrintAuditTable_EscapesTenantFields(t *testing.T) {
	fields := map[string]func(v string) audit.AuditEntry{
		"username": func(v string) audit.AuditEntry { return audit.AuditEntry{Username: v, ResourceType: "box"} },
		"resource id": func(v string) audit.AuditEntry {
			return audit.AuditEntry{Username: "u", ResourceType: "box", ResourceID: v}
		},
	}
	for name, mk := range fields {
		for _, h := range inlineHostile {
			t.Run(name+"/"+h.name, func(t *testing.T) {
				var b bytes.Buffer
				printAuditTable(&b, []audit.AuditEntry{mk("bad" + h.ctrl + "FORGED")})
				out := b.String()
				// the audit table truncates cells, so only assert the raw
				// bytes are gone and the escaped prefix is visible.
				assertNoRawInline(t, out)
				if !bytes.Contains(b.Bytes(), []byte("bad"+h.want)) {
					t.Errorf("escaped value not shown:\n%q", out)
				}
			})
		}
	}
}
