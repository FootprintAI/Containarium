package guardraildropin

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// elfWith builds a minimal 64-bit little-endian ELF executable whose only
// program header is of the given type: PT_INTERP is what a cgo build (a
// dynamically linked binary) carries, PT_LOAD alone is what CGO_ENABLED=0
// produces.
func elfWith(t *testing.T, prog elf.ProgType) []byte {
	t.Helper()
	var buf bytes.Buffer
	hdr := elf.Header64{
		Type:      uint16(elf.ET_EXEC),
		Machine:   uint16(elf.EM_X86_64),
		Version:   uint32(elf.EV_CURRENT),
		Phoff:     64,
		Ehsize:    64,
		Phentsize: 56,
		Phnum:     1,
	}
	copy(hdr.Ident[:], elf.ELFMAG)
	hdr.Ident[elf.EI_CLASS] = byte(elf.ELFCLASS64)
	hdr.Ident[elf.EI_DATA] = byte(elf.ELFDATA2LSB)
	hdr.Ident[elf.EI_VERSION] = byte(elf.EV_CURRENT)
	if err := binary.Write(&buf, binary.LittleEndian, hdr); err != nil {
		t.Fatal(err)
	}
	if err := binary.Write(&buf, binary.LittleEndian, elf.Prog64{Type: uint32(prog), Off: 120, Filesz: 1, Memsz: 1}); err != nil {
		t.Fatal(err)
	}
	buf.WriteByte(0)
	return buf.Bytes()
}

// #3823: the refusal must be recognisable by callers, so a daemon whose own
// binary is dynamically linked can say "precondition" instead of "internal
// error", through every layer that wraps it on the way to the API.
func TestRequireStaticELF_RefusalIsTheTypedSentinel(t *testing.T) {
	dynamic := elfWith(t, elf.PT_INTERP)
	err := requireStaticELF(bytes.NewReader(dynamic))
	if !errors.Is(err, ErrHookBinaryNotStatic) {
		t.Fatalf("a dynamically linked ELF: err = %v, want ErrHookBinaryNotStatic", err)
	}
	if !strings.Contains(err.Error(), "dynamically linked") {
		t.Errorf("the reason is lost: %q", err)
	}
	// The real path wraps it twice: openHookBinary, then install's "open hook binary".
	wrapped := fmt.Errorf("open hook binary: %w", fmt.Errorf("hook binary /proc/self/exe: %w; build ...", err))
	if !errors.Is(wrapped, ErrHookBinaryNotStatic) {
		t.Fatal("the sentinel does not survive the wrapping on the enable path")
	}

	if err := requireStaticELF(strings.NewReader("#!/bin/sh\necho not a binary\n")); !errors.Is(err, ErrHookBinaryNotStatic) {
		t.Fatalf("a script: err = %v, want ErrHookBinaryNotStatic", err)
	}
}

func TestRequireStaticELF_AcceptsAStaticExecutable(t *testing.T) {
	if err := requireStaticELF(bytes.NewReader(elfWith(t, elf.PT_LOAD))); err != nil {
		t.Fatalf("a static ELF was refused: %v", err)
	}
}

// The daemon checks at startup, so an operator learns that the hook can never
// be switched on before the first enable fails.
func TestCheckHookBinary(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, b []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, b, 0o755); err != nil {
			t.Fatal(err)
		}
		return p
	}
	if err := CheckHookBinary(write("static", elfWith(t, elf.PT_LOAD))); err != nil {
		t.Errorf("static binary: %v", err)
	}
	err := CheckHookBinary(write("dynamic", elfWith(t, elf.PT_INTERP)))
	if !errors.Is(err, ErrHookBinaryNotStatic) {
		t.Errorf("dynamic binary: err = %v, want ErrHookBinaryNotStatic", err)
	}
	if err := CheckHookBinary(filepath.Join(dir, "missing")); err == nil || errors.Is(err, ErrHookBinaryNotStatic) {
		t.Errorf("a missing file is an open error, not the static-binary refusal: %v", err)
	}
}
