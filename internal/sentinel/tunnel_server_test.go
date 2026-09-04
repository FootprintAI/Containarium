package sentinel

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLoopbackPortsFor(t *testing.T) {
	tests := []struct {
		name       string
		ports      []int
		httpsPort  int
		publicPort int
		want       []int
	}{
		{
			name:      "non-primary backend still excludes the sentinel's own https port",
			ports:     []int{22, 8080, 443},
			httpsPort: 443,
			want:      []int{22, 8080},
		},
		{
			name:       "promoted primary excludes its public port too",
			ports:      []int{22, 8080, 443},
			httpsPort:  443,
			publicPort: 443,
			want:       []int{22, 8080},
		},
		{
			name:       "public port distinct from the https port is excluded on top of it",
			ports:      []int{22, 8080, 443, 9443},
			httpsPort:  443,
			publicPort: 9443,
			want:       []int{22, 8080},
		},
		{
			name:      "no https port configured filters nothing",
			ports:     []int{22, 8080, 443},
			httpsPort: 0,
			want:      []int{22, 8080, 443},
		},
		{
			name:      "port not present is a no-op",
			ports:     []int{22, 8080},
			httpsPort: 443,
			want:      []int{22, 8080},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := loopbackPortsFor(tt.ports, tt.httpsPort, tt.publicPort)
			assert.Equal(t, tt.want, got)
		})
	}
}
