package server

import "sync/atomic"

// liveValue is a race-safe holder for a value set after the server starts
// serving — an interface a store family's late install wires (#3329).
// Its zero value holds the zero T, so a server built as a struct literal
// needs no setup.
type liveValue[T any] struct {
	p atomic.Pointer[T]
}

func (v *liveValue[T]) load() T {
	if p := v.p.Load(); p != nil {
		return *p
	}
	var zero T
	return zero
}

func (v *liveValue[T]) store(x T) { v.p.Store(&x) }
