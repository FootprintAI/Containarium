package cmd

import (
	"bytes"
	"testing"
)

func TestDetachEscape_FiresOnCtrlAThenQ(t *testing.T) {
	src := bytes.NewReader([]byte("hello\x01qworld"))
	d, detach := newDetachEscape(src)

	buf := make([]byte, 64)
	n, err := d.Read(buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != len("hello\x01qworld") {
		t.Fatalf("expected to read all bytes in one call, got %d", n)
	}

	select {
	case <-detach:
	default:
		t.Fatal("expected detach channel to be closed after <ctrl>+a q")
	}
}

func TestDetachEscape_DoesNotFireOnQAlone(t *testing.T) {
	src := bytes.NewReader([]byte("just q with no ctrl-a"))
	d, detach := newDetachEscape(src)

	buf := make([]byte, 64)
	if _, err := d.Read(buf); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	select {
	case <-detach:
		t.Fatal("detach fired without the <ctrl>+a prefix")
	default:
	}
}

func TestDetachEscape_CtrlAThenOtherKeyDoesNotArmAcrossReads(t *testing.T) {
	// <ctrl>+a followed by something other than 'q' should not leave the
	// escape armed for a later, unrelated 'q'.
	src := bytes.NewReader([]byte("\x01xq"))
	d, detach := newDetachEscape(src)

	buf := make([]byte, 64)
	if _, err := d.Read(buf); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	select {
	case <-detach:
		t.Fatal("detach fired even though <ctrl>+a was followed by a non-'q' byte")
	default:
	}
}

func TestDetachEscape_OnlyFiresOnce(t *testing.T) {
	src := bytes.NewReader([]byte("\x01q\x01q"))
	d, detach := newDetachEscape(src)

	buf := make([]byte, 64)
	if _, err := d.Read(buf); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Closing an already-closed channel would panic; reading it twice here
	// (once via select, once via receive) proves it was only closed once.
	<-detach
	select {
	case <-detach:
	default:
		t.Fatal("channel should read as already-closed")
	}
}

func TestConsoleWebSocketURL(t *testing.T) {
	cases := []struct {
		name       string
		serverAddr string
		username   string
		want       string
		wantErr    bool
	}{
		{"http scheme becomes ws", "http://daemon.example.com:8080", "alice", "ws://daemon.example.com:8080/v1/containers/alice/console-attach", false},
		{"https scheme becomes wss", "https://daemon.example.com", "alice", "wss://daemon.example.com/v1/containers/alice/console-attach", false},
		{"bare host defaults to http/ws", "daemon.example.com:8080", "alice", "ws://daemon.example.com:8080/v1/containers/alice/console-attach", false},
		{"trailing slash stripped", "http://daemon.example.com/", "alice", "ws://daemon.example.com/v1/containers/alice/console-attach", false},
		{"username is path-escaped", "http://daemon.example.com", "a/b", "ws://daemon.example.com/v1/containers/a%2Fb/console-attach", false},
		{"unsupported scheme rejected", "ws://daemon.example.com", "alice", "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := consoleWebSocketURL(c.serverAddr, c.username)
			if c.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got url %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != c.want {
				t.Fatalf("got %q, want %q", got, c.want)
			}
		})
	}
}
