package client

import (
	"errors"
	"testing"
)

// TestNewGRPCClient_EmptyServerRejected pins #1776: an empty server address
// must fail fast with ErrNoServerConfigured, before ever touching cert
// paths or attempting to dial.
func TestNewGRPCClient_EmptyServerRejected(t *testing.T) {
	_, err := NewGRPCClient("", "", false)
	if !errors.Is(err, ErrNoServerConfigured) {
		t.Errorf("NewGRPCClient(\"\", ...) error = %v, want ErrNoServerConfigured", err)
	}
}
