package safecast

import (
	"math"
	"testing"
)

func TestI32(t *testing.T) {
	cases := []struct {
		in   int64
		want int32
	}{
		{0, 0},
		{42, 42},
		{-42, -42},
		{math.MaxInt32, math.MaxInt32},
		{math.MinInt32, math.MinInt32},
		{math.MaxInt32 + 1, math.MaxInt32}, // saturate high
		{math.MinInt32 - 1, math.MinInt32}, // saturate low
		{math.MaxInt64, math.MaxInt32},
		{math.MinInt64, math.MinInt32},
	}
	for _, c := range cases {
		if got := I32(c.in); got != c.want {
			t.Errorf("I32(%d) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestI64FromU64(t *testing.T) {
	cases := []struct {
		in   uint64
		want int64
	}{
		{0, 0},
		{42, 42},
		{math.MaxInt64, math.MaxInt64},
		{math.MaxInt64 + 1, math.MaxInt64}, // saturate
		{math.MaxUint64, math.MaxInt64},
	}
	for _, c := range cases {
		if got := I64FromU64(c.in); got != c.want {
			t.Errorf("I64FromU64(%d) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestU64FromI64(t *testing.T) {
	cases := []struct {
		in   int64
		want uint64
	}{
		{0, 0},
		{42, 42},
		{-1, 0},            // clamp negative
		{math.MinInt64, 0}, // clamp negative
		{math.MaxInt64, math.MaxInt64},
	}
	for _, c := range cases {
		if got := U64FromI64(c.in); got != c.want {
			t.Errorf("U64FromI64(%d) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestU32(t *testing.T) {
	cases := []struct {
		in   int64
		want uint32
	}{
		{0, 0},
		{42, 42},
		{-1, 0}, // negative clamps to 0
		{math.MinInt64, 0},
		{math.MaxUint32, math.MaxUint32},
		{math.MaxUint32 + 1, math.MaxUint32}, // saturate
		{math.MaxInt64, math.MaxUint32},
	}
	for _, c := range cases {
		if got := U32(c.in); got != c.want {
			t.Errorf("U32(%d) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestU32FromUint(t *testing.T) {
	if got := U32FromUint(uint(42)); got != 42 {
		t.Errorf("U32FromUint(42) = %d, want 42", got)
	}
	if got := U32FromUint(uint64(math.MaxUint32) + 1); got != math.MaxUint32 {
		t.Errorf("U32FromUint(MaxUint32+1) = %d, want MaxUint32", got)
	}
}

func TestU16FromUint(t *testing.T) {
	if got := U16FromUint(uint32(6379)); got != 6379 {
		t.Errorf("U16FromUint(6379) = %d, want 6379", got)
	}
	if got := U16FromUint(uint32(math.MaxUint16)); got != math.MaxUint16 {
		t.Errorf("U16FromUint(MaxUint16) = %d, want MaxUint16", got)
	}
	if got := U16FromUint(uint32(math.MaxUint16) + 1); got != math.MaxUint16 {
		t.Errorf("U16FromUint(MaxUint16+1) = %d, want clamp to MaxUint16", got)
	}
}

func TestI16(t *testing.T) {
	cases := []struct {
		in   int32
		want int16
	}{
		{0, 0},
		{42, 42},
		{-42, -42},
		{math.MaxInt16, math.MaxInt16},
		{math.MinInt16, math.MinInt16},
		{math.MaxInt16 + 1, math.MaxInt16},
		{math.MinInt16 - 1, math.MinInt16},
	}
	for _, c := range cases {
		if got := I16(c.in); got != c.want {
			t.Errorf("I16(%d) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestI32FromU32(t *testing.T) {
	if got := I32FromU32(42); got != 42 {
		t.Errorf("I32FromU32(42) = %d, want 42", got)
	}
	if got := I32FromU32(math.MaxUint32); got != math.MaxInt32 {
		t.Errorf("I32FromU32(MaxUint32) = %d, want MaxInt32", got)
	}
}

func TestU8(t *testing.T) {
	cases := []struct {
		in   int32
		want uint8
	}{
		{0, 0},
		{200, 200},
		{255, 255},
		{-1, 0},    // negative clamps to 0
		{256, 255}, // saturate
		{1000, 255},
	}
	for _, c := range cases {
		if got := U8(c.in); got != c.want {
			t.Errorf("U8(%d) = %d, want %d", c.in, got, c.want)
		}
	}
}
