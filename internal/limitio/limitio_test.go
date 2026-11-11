package limitio

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
	"testing/iotest"
)

func TestReadAll_UnderCapReturnsEverything(t *testing.T) {
	got, err := ReadAll(strings.NewReader("hello"), 10)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(got) != "hello" {
		t.Fatalf("got %q, want %q", got, "hello")
	}
}

func TestReadAll_ExactlyCapIsNotTooLarge(t *testing.T) {
	got, err := ReadAll(strings.NewReader("12345"), 5)
	if err != nil {
		t.Fatalf("ReadAll at exactly the cap: %v", err)
	}
	if string(got) != "12345" {
		t.Fatalf("got %q, want %q", got, "12345")
	}
}

func TestReadAll_CapPlusOneIsTooLarge(t *testing.T) {
	got, err := ReadAll(strings.NewReader("123456"), 5)
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("err = %v, want ErrTooLarge", err)
	}
	var tl *TooLargeError
	if !errors.As(err, &tl) || tl.Limit != 5 {
		t.Fatalf("err = %#v, want *TooLargeError{Limit: 5}", err)
	}
	if string(got) != "12345" {
		t.Fatalf("got %q, want the first 5 bytes", got)
	}
}

func TestReadAll_ZeroCap(t *testing.T) {
	got, err := ReadAll(strings.NewReader(""), 0)
	if err != nil || len(got) != 0 {
		t.Fatalf("empty input at zero cap: got %q, %v", got, err)
	}
	got, err = ReadAll(strings.NewReader("x"), 0)
	if !errors.Is(err, ErrTooLarge) || len(got) != 0 {
		t.Fatalf("one byte at zero cap: got %q, %v, want empty + ErrTooLarge", got, err)
	}
}

func TestReadAll_NegativeCapActsAsZero(t *testing.T) {
	got, err := ReadAll(strings.NewReader("x"), -1)
	if !errors.Is(err, ErrTooLarge) || len(got) != 0 {
		t.Fatalf("got %q, %v, want empty + ErrTooLarge", got, err)
	}
}

// endless never returns EOF: an unbounded io.ReadAll on it never returns.
type endless struct{ n int64 }

func (e *endless) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'y'
	}
	e.n += int64(len(p))
	return len(p), nil
}

func TestReadAll_StopsReadingAnEndlessSource(t *testing.T) {
	src := &endless{}
	got, err := ReadAll(src, 1<<16)
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("err = %v, want ErrTooLarge", err)
	}
	if len(got) != 1<<16 {
		t.Fatalf("len = %d, want %d", len(got), 1<<16)
	}
	// It may read one buffer past the cap to detect the overflow, never
	// unboundedly more.
	if src.n > 1<<17 {
		t.Fatalf("read %d bytes from the source for a %d-byte cap", src.n, 1<<16)
	}
}

func TestReadAll_PassesThroughReadErrors(t *testing.T) {
	boom := errors.New("boom")
	_, err := ReadAll(iotest.ErrReader(boom), 10)
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the underlying read error", err)
	}
	if errors.Is(err, ErrTooLarge) {
		t.Fatalf("a read error is not a too-large error")
	}
}

func TestReadAll_MaxInt64CapDoesNotOverflow(t *testing.T) {
	got, err := ReadAll(strings.NewReader("abc"), 1<<63-1)
	if err != nil || string(got) != "abc" {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestTooLargeError_Message(t *testing.T) {
	err := &TooLargeError{Limit: 42}
	if !strings.Contains(err.Error(), "42") {
		t.Fatalf("message %q does not name the limit", err.Error())
	}
}

func TestBuffer_UnderCapKeepsEverything(t *testing.T) {
	b := NewBuffer(10)
	n, err := io.WriteString(b, "hello")
	if n != 5 || err != nil {
		t.Fatalf("Write = %d, %v", n, err)
	}
	if b.String() != "hello" || b.Truncated() || b.Err() != nil {
		t.Fatalf("buffer = %q truncated=%v err=%v", b.String(), b.Truncated(), b.Err())
	}
}

func TestBuffer_ExactlyCapIsNotTruncated(t *testing.T) {
	b := NewBuffer(5)
	_, _ = io.WriteString(b, "123")
	_, _ = io.WriteString(b, "45")
	if b.String() != "12345" || b.Truncated() || b.Err() != nil {
		t.Fatalf("buffer = %q truncated=%v err=%v", b.String(), b.Truncated(), b.Err())
	}
}

func TestBuffer_CapPlusOneKeepsPrefixAndReportsTooLarge(t *testing.T) {
	b := NewBuffer(5)
	_, _ = io.WriteString(b, "123")
	// A writer that errors would stop the producer mid-stream and could
	// leave the process blocked on a full pipe, so the excess is
	// accepted and dropped.
	n, err := io.WriteString(b, "456")
	if n != 3 || err != nil {
		t.Fatalf("Write past the cap = %d, %v, want 3, nil", n, err)
	}
	if b.String() != "12345" {
		t.Fatalf("buffer = %q, want %q", b.String(), "12345")
	}
	if !b.Truncated() {
		t.Fatal("Truncated() = false, want true")
	}
	var tl *TooLargeError
	if !errors.As(b.Err(), &tl) || tl.Limit != 5 || !errors.Is(b.Err(), ErrTooLarge) {
		t.Fatalf("Err() = %v, want *TooLargeError{Limit: 5}", b.Err())
	}
	if !bytes.Equal(b.Bytes(), []byte("12345")) {
		t.Fatalf("Bytes() = %q", b.Bytes())
	}
}

func TestBuffer_ZeroCap(t *testing.T) {
	b := NewBuffer(0)
	if b.Err() != nil {
		t.Fatalf("empty zero-cap buffer: Err() = %v", b.Err())
	}
	n, err := b.Write(nil)
	if n != 0 || err != nil || b.Truncated() {
		t.Fatalf("empty write at zero cap: %d, %v, truncated=%v", n, err, b.Truncated())
	}
	_, _ = b.Write([]byte("x"))
	if b.Len() != 0 || !b.Truncated() {
		t.Fatalf("one byte at zero cap: len=%d truncated=%v", b.Len(), b.Truncated())
	}
}

func TestBuffer_ResetClearsTruncation(t *testing.T) {
	b := NewBuffer(2)
	_, _ = io.WriteString(b, "abc")
	b.Reset()
	if b.Len() != 0 || b.Truncated() || b.Err() != nil {
		t.Fatalf("after Reset: len=%d truncated=%v err=%v", b.Len(), b.Truncated(), b.Err())
	}
	_, _ = io.WriteString(b, "ab")
	if b.String() != "ab" || b.Truncated() {
		t.Fatalf("after Reset + write: %q truncated=%v", b.String(), b.Truncated())
	}
}
