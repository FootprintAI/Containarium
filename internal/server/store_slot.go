package server

import "sync/atomic"

// storeSlot is a store family's atomic-swap target (#3326): its server reads
// the current store through Load on every call, so a durable store stored
// later reaches it without re-wiring. Until then it holds the fail-closed
// stand-in. The zero value is ready to use and holds T's zero value, so a
// slot can be a plain field of a server struct (#3333).
//
// It lives outside store_recovery.go, without that file's build constraint,
// because servers built into every binary hold one.
type storeSlot[T any] struct {
	cur atomic.Pointer[storeSlotRef[T]]
}

type storeSlotRef[T any] struct{ v T }

// newStoreSlot returns a slot serving standIn.
func newStoreSlot[T any](standIn T) *storeSlot[T] {
	s := &storeSlot[T]{}
	s.Store(standIn)
	return s
}

// Load returns the current store, or T's zero value if none was stored.
func (s *storeSlot[T]) Load() T {
	if r := s.cur.Load(); r != nil {
		return r.v
	}
	var zero T
	return zero
}

// Store swaps v in. Safe while serving.
func (s *storeSlot[T]) Store(v T) { s.cur.Store(&storeSlotRef[T]{v: v}) }
