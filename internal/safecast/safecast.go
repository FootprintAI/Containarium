// Package safecast provides overflow-safe integer conversions.
//
// Each converter SATURATES (clamps) at the destination type's bounds instead
// of silently wrapping, so a value that doesn't fit yields the nearest
// representable value rather than a corrupted one. This addresses gosec G115
// (integer overflow conversion) at the call sites in a single, tested place
// rather than scattering bounds checks or suppressions across the tree.
//
// Use these wherever a wider/signed-mismatched value flows into a narrower or
// differently-signed type — counts/lengths into proto int32 fields, byte sizes
// from an unsigned source into int64, ports between int32 and uint32, etc. The
// inputs in this codebase are almost always already in range; the clamp is a
// safety net that turns a theoretical wrap into a benign saturation.
package safecast

import "math"

// I32 converts a signed integer to int32, clamping to [MinInt32, MaxInt32].
func I32[T ~int | ~int64](v T) int32 {
	if v > math.MaxInt32 {
		return math.MaxInt32
	}
	if v < math.MinInt32 {
		return math.MinInt32
	}
	return int32(v)
}

// I64FromU64 converts uint64 to int64, clamping at MaxInt64.
func I64FromU64(v uint64) int64 {
	if v > math.MaxInt64 {
		return math.MaxInt64
	}
	return int64(v)
}

// U32 converts a signed integer to uint32, clamping to [0, MaxUint32].
func U32[T ~int | ~int32 | ~int64](v T) uint32 {
	if v < 0 {
		return 0
	}
	if uint64(v) > math.MaxUint32 {
		return math.MaxUint32
	}
	return uint32(v)
}

// I16 converts a signed integer to int16, clamping to [MinInt16, MaxInt16].
func I16[T ~int | ~int32 | ~int64](v T) int16 {
	if v > math.MaxInt16 {
		return math.MaxInt16
	}
	if v < math.MinInt16 {
		return math.MinInt16
	}
	return int16(v)
}

// I32FromU32 converts uint32 to int32, clamping at MaxInt32.
func I32FromU32(v uint32) int32 {
	if v > math.MaxInt32 {
		return math.MaxInt32
	}
	return int32(v)
}

// U32FromUint converts an unsigned integer to uint32, clamping at MaxUint32.
func U32FromUint[T ~uint | ~uint64](v T) uint32 {
	if v > math.MaxUint32 {
		return math.MaxUint32
	}
	return uint32(v)
}

// U8 converts a signed integer to uint8, clamping to [0, 255].
func U8[T ~int | ~int32 | ~int64](v T) uint8 {
	if v < 0 {
		return 0
	}
	if v > math.MaxUint8 {
		return math.MaxUint8
	}
	return uint8(v)
}
