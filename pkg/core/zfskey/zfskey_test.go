package zfskey

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"testing"
)

func mustKey(t *testing.T, b []byte) Key {
	t.Helper()
	k, err := NewKey(b)
	if err != nil {
		t.Fatalf("NewKey: %v", err)
	}
	return k
}

func testKeyBytes(fill byte) []byte {
	return bytes.Repeat([]byte{fill}, KeyLen)
}

// AC: key material never appears in logs, errors, or any String()/
// marshalled form.
//
// This is asserted rather than reviewed because every one of these is a
// path key bytes have escaped through in real systems: a %v in a log
// line, a %#v in a debug dump, a struct marshalled into an API response.
func TestKeyNeverRendersMaterial(t *testing.T) {
	secret := []byte("SUPERSECRETKEYMATERIAL0123456789") // exactly KeyLen
	if len(secret) != KeyLen {
		t.Fatalf("fixture is %d bytes, want %d", len(secret), KeyLen)
	}
	k := mustKey(t, secret)

	renderings := map[string]string{
		"%v":       fmt.Sprintf("%v", k),
		"%s":       fmt.Sprintf("key=%s", k),
		"%+v":      fmt.Sprintf("%+v", k),
		"%#v":      fmt.Sprintf("%#v", k),
		"%q":       fmt.Sprintf("%q", k),
		"String()": k.String(),
		"error":    fmt.Errorf("load failed for %v", k).Error(),
	}

	// A Key reached indirectly — nested in a struct — must redact too.
	type wrapper struct {
		Tenant string
		Key    Key
	}
	renderings["nested %v"] = fmt.Sprintf("%v", wrapper{Tenant: "alice", Key: k})
	renderings["nested %#v"] = fmt.Sprintf("%#v", wrapper{Tenant: "alice", Key: k})

	j, err := json.Marshal(wrapper{Tenant: "alice", Key: k})
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	renderings["json"] = string(j)

	txt, err := k.MarshalText()
	if err != nil {
		t.Fatalf("MarshalText: %v", err)
	}
	renderings["text"] = string(txt)

	// And through the standard logger, which is how the daemon logs.
	var logbuf bytes.Buffer
	lg := log.New(&logbuf, "", 0)
	lg.Printf("[zfs] loaded key %v for tenant %s", k, "alice")
	renderings["log.Printf"] = logbuf.String()

	for name, got := range renderings {
		if strings.Contains(got, string(secret)) {
			t.Errorf("%s leaked raw key material: %q", name, got)
		}
		// Also catch a hex/base64 rendering of the same bytes.
		if strings.Contains(got, "5355504552") { // hex of "SUPER"
			t.Errorf("%s leaked hex-encoded key material: %q", name, got)
		}
		if strings.Contains(got, "U1VQRVJTRUNSRVQ") { // base64 of "SUPERSECRET"
			t.Errorf("%s leaked base64-encoded key material: %q", name, got)
		}
	}
}

// Bytes() is the one sanctioned way out, and it must hand back a copy —
// otherwise a caller can mutate the cached key through the slice.
func TestKeyBytesReturnsACopy(t *testing.T) {
	orig := testKeyBytes(0xAB)
	k := mustKey(t, orig)

	got := k.Bytes()
	if !bytes.Equal(got, orig) {
		t.Fatalf("Bytes() = %x, want %x", got, orig)
	}

	got[0] = 0x00
	if again := k.Bytes(); again[0] != 0xAB {
		t.Error("mutating the returned slice corrupted the key")
	}
}

// NewKey copies its input, so a caller reusing or zeroing its buffer
// cannot corrupt an already-constructed key.
func TestNewKeyCopiesInput(t *testing.T) {
	buf := testKeyBytes(0x11)
	k := mustKey(t, buf)

	for i := range buf {
		buf[i] = 0
	}
	if k.Bytes()[0] != 0x11 {
		t.Error("zeroing the caller's buffer corrupted the key")
	}
}

// ZFS keyformat=raw wants exactly KeyLen bytes; anything else is rejected
// here rather than surfacing later as an opaque `zfs load-key` failure.
func TestNewKeyRejectsWrongLength(t *testing.T) {
	for _, tc := range []struct {
		name string
		n    int
	}{
		{"empty", 0},
		{"one short", KeyLen - 1},
		{"one long", KeyLen + 1},
		{"way short", 8},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewKey(bytes.Repeat([]byte{1}, tc.n))
			if err == nil {
				t.Fatalf("NewKey accepted a %d-byte key", tc.n)
			}
			if !strings.Contains(err.Error(), "32") {
				t.Errorf("error should state the required length, got %q", err)
			}
		})
	}
}

// An error about a bad key must not quote the material it rejected.
func TestNewKeyErrorDoesNotEchoInput(t *testing.T) {
	bad := []byte("short-but-still-secret")
	_, err := NewKey(bad)
	if err == nil {
		t.Fatal("expected rejection")
	}
	if strings.Contains(err.Error(), string(bad)) {
		t.Errorf("rejection error echoed the input: %q", err)
	}
}
