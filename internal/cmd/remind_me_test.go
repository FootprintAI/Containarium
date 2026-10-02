package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNormalizeEmail(t *testing.T) {
	ok := map[string]string{" Alice@Example.com ": "alice@example.com", "bob+box@example.org": "bob+box@example.org"}
	for in, want := range ok {
		if got, err := normalizeEmail(in); err != nil || got != want {
			t.Errorf("%q → %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"", "not-an-email", "Alice <alice@example.com>", "a@b", "two@x.com, three@y.com"} {
		if got, err := normalizeEmail(in); err == nil {
			t.Errorf("%q accepted as %q", in, got)
		}
	}
}

func TestRemindMeCmd_WriteAndClear(t *testing.T) {
	old := remindMeFile
	remindMeFile = filepath.Join(t.TempDir(), "remind-me")
	t.Cleanup(func() { remindMeFile = old; remindMeClear = false })

	// Not an anonymous box: the daemon never created the file.
	if err := remindMeCmd.RunE(remindMeCmd, []string{"alice@example.com"}); err == nil || !strings.Contains(err.Error(), "not an anonymous box") {
		t.Fatalf("missing file: %v", err)
	}
	if err := os.WriteFile(remindMeFile, nil, 0o666); err != nil {
		t.Fatal(err)
	}
	var sb strings.Builder
	remindMeCmd.SetOut(&sb)
	if err := remindMeCmd.RunE(remindMeCmd, []string{"Alice@Example.com"}); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(remindMeFile); string(got) != "alice@example.com\n" {
		t.Errorf("file = %q", got)
	}
	if !strings.Contains(sb.String(), "alice@example.com") {
		t.Errorf("output = %q", sb.String())
	}
	// Replace.
	if err := remindMeCmd.RunE(remindMeCmd, []string{"bob@example.com"}); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(remindMeFile); string(got) != "bob@example.com\n" {
		t.Errorf("replace: file = %q", got)
	}
	// Clear.
	remindMeClear = true
	if err := remindMeCmd.RunE(remindMeCmd, nil); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(remindMeFile); string(got) != "" {
		t.Errorf("clear: file = %q", got)
	}
	if err := remindMeCmd.RunE(remindMeCmd, []string{"x@example.com"}); err == nil {
		t.Error("--clear with an address must error")
	}
	remindMeClear = false
	if err := remindMeCmd.RunE(remindMeCmd, []string{"nope"}); err == nil {
		t.Error("invalid address must error")
	}
}
