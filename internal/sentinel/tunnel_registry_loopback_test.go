package sentinel

import "testing"

// TestIsAlreadyExistsErr pins the detection logic behind addLoopbackAlias's
// idempotency fix: only "RTNETLINK answers: File exists" (the alias is
// already there — safe to treat as success) should be swallowed. Anything
// else must still surface as a real failure.
func TestIsAlreadyExistsErr(t *testing.T) {
	cases := []struct {
		name   string
		output string
		want   bool
	}{
		{
			name:   "real iproute2 already-exists output",
			output: "RTNETLINK answers: File exists\n",
			want:   true,
		},
		{
			name:   "already-exists text embedded in a longer message",
			output: "Error: ipv4: Address already assigned.\nRTNETLINK answers: File exists\n",
			want:   true,
		},
		{
			name:   "empty output (e.g. success)",
			output: "",
			want:   false,
		},
		{
			name:   "invalid address",
			output: "Error: any valid prefix is expected rather than \"bogus\".\n",
			want:   false,
		},
		{
			name:   "missing interface",
			output: "Cannot find device \"lo\"\n",
			want:   false,
		},
		{
			name:   "permission denied",
			output: "RTNETLINK answers: Operation not permitted\n",
			want:   false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isAlreadyExistsErr([]byte(tc.output)); got != tc.want {
				t.Errorf("isAlreadyExistsErr(%q) = %v, want %v", tc.output, got, tc.want)
			}
		})
	}
}
