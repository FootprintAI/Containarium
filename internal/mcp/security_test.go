package mcp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNormalizeZapRisk(t *testing.T) {
	cases := []struct{ in, want string }{
		{"High", "high"},
		{"medium", "medium"},
		{"LOW", "low"},
		{"Informational", "info"},
		{"Info", "info"},
		{"unknown-stuff", "info"},
		{"", "info"},
	}
	for _, c := range cases {
		assert.Equal(t, c.want, normalizeZapRisk(c.in), "input %q", c.in)
	}
}

func TestGetInt64Arg(t *testing.T) {
	cases := []struct {
		name string
		args map[string]interface{}
		key  string
		want int64
		ok   bool
	}{
		{"missing", map[string]interface{}{}, "id", 0, false},
		{"int64", map[string]interface{}{"id": int64(42)}, "id", 42, true},
		{"int", map[string]interface{}{"id": 7}, "id", 7, true},
		{"float64 (JSON shape)", map[string]interface{}{"id": float64(13)}, "id", 13, true},
		{"string-parsable", map[string]interface{}{"id": "99"}, "id", 99, true},
		{"string-unparseable", map[string]interface{}{"id": "abc"}, "id", 0, false},
		{"wrong type", map[string]interface{}{"id": []int{1, 2}}, "id", 0, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := getInt64Arg(c.args, c.key)
			assert.Equal(t, c.want, got)
			assert.Equal(t, c.ok, ok)
		})
	}
}
