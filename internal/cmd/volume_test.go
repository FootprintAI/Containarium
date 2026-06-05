package cmd

import "testing"

func TestParseSizeBytes(t *testing.T) {
	cases := []struct {
		in      string
		want    int64
		wantErr bool
	}{
		{"50GB", 50_000_000_000, false},
		{"1TB", 1_000_000_000_000, false},
		{"500MB", 500_000_000, false},
		{"1GiB", 1 << 30, false},
		{"2TiB", 2 << 40, false},
		{"1G", 1 << 30, false}, // bare G is binary
		{"1024", 1024, false},  // bare number = bytes
		{"  10GB  ", 10_000_000_000, false},
		{"", 0, true},
		{"notasize", 0, true},
		{"GB", 0, true},
	}
	for _, tc := range cases {
		got, err := parseSizeBytes(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("parseSizeBytes(%q) = %d, want error", tc.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseSizeBytes(%q): unexpected error %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("parseSizeBytes(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}
