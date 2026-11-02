package cmd

import (
	"reflect"
	"strings"
	"testing"
)

func TestValidateBrowserURL(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{"https ok", "https://app.example.com/cli/verify?code=ABCD-1234", false},
		{"https with encoded amp ok", "https://app.example.com/v?a=1%26b=2", false},
		{"http loopback ok", "http://127.0.0.1:8080/cli/verify", false},
		{"http localhost ok", "http://localhost:3000/cli", false},
		{"http ipv6 loopback ok", "http://[::1]:8080/cli", false},
		{"http non-loopback rejected", "http://app.example.com/cli", true},
		{"file scheme rejected", "file:///etc/passwd", true},
		{"file scheme with host rejected", "file://host/share/x", true},
		{"ftp scheme rejected", "ftp://app.example.com/x", true},
		{"javascript scheme rejected", "javascript:alert(1)", true},
		{"no scheme rejected", "app.example.com/cli", true},
		{"empty rejected", "", true},
		{"no host rejected", "https:///path", true},
		{"ampersand rejected", "https://app.example.com/v?a=1&b=2", true},
		{"pipe rejected", "https://app.example.com/v|calc", true},
		{"caret rejected", "https://app.example.com/v^x", true},
		{"double quote rejected", "https://app.example.com/v\"x", true},
		{"newline rejected", "https://app.example.com/v\nx", true},
		{"carriage return rejected", "https://app.example.com/v\rx", true},
		{"space rejected", "https://app.example.com/v x", true},
		{"less-than rejected", "https://app.example.com/v<x", true},
		{"greater-than rejected", "https://app.example.com/v>x", true},
		{"backtick rejected", "https://app.example.com/v`x", true},
		{"semicolon rejected", "https://app.example.com/v;x", true},
		{"NUL rejected", "https://app.example.com/v\x00x", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateBrowserURL(tc.url)
			if (err != nil) != tc.wantErr {
				t.Fatalf("validateBrowserURL(%q) err=%v, wantErr=%v", tc.url, err, tc.wantErr)
			}
		})
	}
}

func TestBrowserCommand(t *testing.T) {
	const u = "https://app.example.com/cli?code=X"
	tests := []struct {
		goos     string
		wantName string
		wantArgs []string
		wantErr  bool
	}{
		{"linux", "xdg-open", []string{u}, false},
		{"darwin", "open", []string{u}, false},
		{"windows", "rundll32", []string{"url.dll,FileProtocolHandler", u}, false},
		{"plan9", "", nil, true},
	}
	for _, tc := range tests {
		t.Run(tc.goos, func(t *testing.T) {
			name, args, err := browserCommand(tc.goos, u)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err=%v wantErr=%v", err, tc.wantErr)
			}
			if name != tc.wantName || !reflect.DeepEqual(args, tc.wantArgs) {
				t.Fatalf("got %q %v, want %q %v", name, args, tc.wantName, tc.wantArgs)
			}
		})
	}
	// Windows must never route through cmd.exe.
	name, args, _ := browserCommand("windows", u)
	hasSlashC := false
	for _, a := range args {
		if strings.EqualFold(a, "/c") {
			hasSlashC = true
		}
	}
	if strings.EqualFold(name, "cmd") || hasSlashC {
		t.Fatalf("windows launcher must not use cmd.exe: %q %v", name, args)
	}
}

func TestOpenBrowserRejectsBadURLBeforeLaunch(t *testing.T) {
	orig := startBrowserCmd
	defer func() { startBrowserCmd = orig }()
	called := false
	startBrowserCmd = func(name string, args ...string) error { called = true; return nil }

	if err := openBrowser("https://app.example.com/v?a=1&calc"); err == nil {
		t.Fatal("expected error for URL with &")
	}
	if called {
		t.Fatal("launcher must not run for an invalid URL")
	}
	if err := openBrowser("https://app.example.com/ok"); err != nil {
		t.Fatalf("valid URL: %v", err)
	}
	if !called {
		t.Fatal("launcher should run for a valid URL")
	}
}
