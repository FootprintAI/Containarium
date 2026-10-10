package agentbox

import (
	"bytes"
	"io"
	"strings"
	"testing"
	"time"
)

const (
	drainReq   = `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"process_start"}}` + "\n"
	drainNotif = `{"jsonrpc":"2.0","method":"notifications/initialized"}` + "\n"
	drainResp  = `{"jsonrpc":"2.0","id":2,"result":{"content":[]}}` + "\n"
)

// readAll drains d in a goroutine and reports when io.EOF surfaced.
func readAll(d *DrainingStdio) <-chan string {
	done := make(chan string, 1)
	go func() {
		b, err := io.ReadAll(d)
		if err != nil {
			done <- "err: " + err.Error()
			return
		}
		done <- string(b)
	}()
	return done
}

// waitPending polls until d has n unanswered requests; the reader runs in
// its own goroutine, so a check straight after starting it would race.
func waitPending(t *testing.T, d *DrainingStdio, n int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for d.Pending() != n {
		if time.Now().After(deadline) {
			t.Fatalf("pending = %d, want %d", d.Pending(), n)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestDrainingStdio_EOFWaitsForTheAnswer(t *testing.T) {
	var out bytes.Buffer
	d := NewDrainingStdio(strings.NewReader(drainNotif+drainReq), &out, 5*time.Second)
	done := readAll(d)

	waitPending(t, d, 1)
	select {
	case got := <-done:
		t.Fatalf("EOF surfaced before the request was answered: %q", got)
	case <-time.After(300 * time.Millisecond):
	}

	if _, err := d.Write([]byte(drainResp)); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-done:
		if got != drainNotif+drainReq {
			t.Fatalf("bytes were not passed through intact: %q", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("EOF still withheld after the response was written")
	}
	if out.String() != drainResp {
		t.Fatalf("response not passed through: %q", out.String())
	}
}

func TestDrainingStdio_NotificationsDoNotBlockEOF(t *testing.T) {
	d := NewDrainingStdio(strings.NewReader(drainNotif), io.Discard, 5*time.Second)
	select {
	case <-readAll(d):
	case <-time.After(2 * time.Second):
		t.Fatal("a notification (no id) must not withhold EOF")
	}
}

func TestDrainingStdio_GraceBoundsTheWait(t *testing.T) {
	d := NewDrainingStdio(strings.NewReader(drainReq), io.Discard, 200*time.Millisecond)
	start := time.Now()
	select {
	case <-readAll(d):
	case <-time.After(3 * time.Second):
		t.Fatal("EOF never surfaced; the grace period did not bound the wait")
	}
	if el := time.Since(start); el < 150*time.Millisecond {
		t.Fatalf("EOF surfaced after %v, before the grace period", el)
	}
}

func TestDrainingStdio_ResponseSplitAcrossWrites(t *testing.T) {
	d := NewDrainingStdio(strings.NewReader(drainReq), io.Discard, 5*time.Second)
	done := readAll(d)
	waitPending(t, d, 1)
	half := len(drainResp) / 2
	_, _ = d.Write([]byte(drainResp[:half]))
	if d.Pending() != 1 {
		t.Fatal("a partial line must not count as a response")
	}
	_, _ = d.Write([]byte(drainResp[half:]))
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("response split across two writes was not recognised")
	}
}

func TestJSONRPCIDKey_NumberAndStringDoNotCollide(t *testing.T) {
	if jsonRPCIDKey(float64(2)) == jsonRPCIDKey("2") {
		t.Fatal("numeric 2 and string \"2\" must be distinct ids")
	}
	if id, ok := jsonRPCRequestID([]byte(`{"id":"abc","method":"x"}`)); !ok || id != jsonRPCIDKey("abc") {
		t.Fatalf("string id: ok=%v id=%q", ok, id)
	}
	if _, ok := jsonRPCResponseID([]byte(`{"id":null,"result":{}}`)); ok {
		t.Fatal("null id is not a trackable response")
	}
}
