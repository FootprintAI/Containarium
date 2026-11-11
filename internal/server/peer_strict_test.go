package server

import (
	"errors"
	"strings"
	"testing"
)

func TestEnforceStrictPeerTLS(t *testing.T) {
	bootstrapErr := errors.New("sentinel unreachable")

	t.Run("strict refuses the http fallback after a failed bootstrap", func(t *testing.T) {
		pool := NewPeerPool("local", "http://sentinel.invalid:8081", nil, "")
		err := pool.EnforceStrictPeerTLS(true, bootstrapErr)
		if err == nil {
			t.Fatal("expected an error when strict and peer mTLS is not enabled")
		}
		if !strings.Contains(err.Error(), "sentinel unreachable") {
			t.Errorf("error should carry the bootstrap cause, got %v", err)
		}
	})

	t.Run("strict refuses the http fallback when bootstrap was skipped", func(t *testing.T) {
		pool := NewPeerPool("local", "http://sentinel.invalid:8081", nil, "")
		if err := pool.EnforceStrictPeerTLS(true, nil); err == nil {
			t.Fatal("expected an error when strict and bootstrap was skipped")
		}
	})

	t.Run("non-strict keeps the fallback", func(t *testing.T) {
		pool := NewPeerPool("local", "http://sentinel.invalid:8081", nil, "")
		if err := pool.EnforceStrictPeerTLS(false, bootstrapErr); err != nil {
			t.Fatalf("default must not change: %v", err)
		}
	})

	t.Run("strict is a no-op when there are no peer calls", func(t *testing.T) {
		pool := NewPeerPool("local", "", nil, "")
		if err := pool.EnforceStrictPeerTLS(true, nil); err != nil {
			t.Fatalf("standalone daemon has nothing to refuse: %v", err)
		}
	})

	t.Run("strict passes when mTLS is active", func(t *testing.T) {
		pool := NewPeerPool("local", "http://sentinel.invalid:8081", nil, "")
		pool.pki = &peerPKI{}
		if err := pool.EnforceStrictPeerTLS(true, nil); err != nil {
			t.Fatalf("mTLS is on: %v", err)
		}
	})
}
