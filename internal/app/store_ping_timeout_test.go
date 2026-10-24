package app

import (
	"context"
	"net"
	"testing"
	"time"
)

// NewStore must not block forever on a Postgres that accepts TCP and never
// answers; daemon startup waits on it before it serves (#2824).
func TestNewStore_PingIsBoundedOnBlackholePostgres(t *testing.T) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = lis.Close() }()
	go func() {
		var held []net.Conn // owned by this goroutine; closed when the listener closes
		for {
			c, err := lis.Accept()
			if err != nil {
				for _, h := range held {
					_ = h.Close()
				}
				return
			}
			held = append(held, c) // never answer the startup message
		}
	}()
	dsn := "postgres://u:p@" + lis.Addr().String() + "/db?sslmode=disable"

	done := make(chan error, 1)
	go func() {
		_, err := NewStore(context.Background(), dsn)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("NewStore succeeded against a blackhole Postgres")
		}
	case <-time.After(15 * time.Second):
		t.Fatal("NewStore still blocked after 15s against a blackhole Postgres (unbounded ping)")
	}
}
