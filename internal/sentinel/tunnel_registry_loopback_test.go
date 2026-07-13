package sentinel

import "testing"

// TestIsAlreadyExistsErr pins the detection logic behind addLoopbackAlias's
// idempotency fix: two distinct iproute2 message formats for the identical
// "alias already there — safe to treat as success" condition must both be
// swallowed. Anything else must still surface as a real failure.
func TestIsAlreadyExistsErr(t *testing.T) {
	cases := []struct {
		name   string
		output string
		want   bool
	}{
		{
			name:   "real iproute2 already-exists output (older/raw-netlink style)",
			output: "RTNETLINK answers: File exists\n",
			want:   true,
		},
		{
			name:   "already-exists text embedded in a longer message",
			output: "Error: ipv4: Address already assigned.\nRTNETLINK answers: File exists\n",
			want:   true,
		},
		// Live-confirmed production output (newer libnl-style iproute2) —
		// this alone, with NO "File exists" substring anywhere, is what
		// actually failed a real BYOC host's tunnel registration on every
		// reconnect until this case was added.
		{
			name:   "standalone newer-iproute2 already-assigned output, no File exists substring",
			output: "Error: ipv4: Address already assigned.\n",
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
