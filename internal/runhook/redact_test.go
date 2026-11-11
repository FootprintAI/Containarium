package runhook

import (
	"strings"
	"testing"
)

func TestRedactor_DefaultListReplacesTokenLookingArguments(t *testing.T) {
	r, err := NewRedactor(nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, arg := range []string{
		"ghp_0123456789abcdefghij0123456789abcdef",
		"--token=github_pat_11ABCDEFG0123456789_abcdefghijklmnopqrstuvwxyz",
		"sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789",
		"AKIAABCDEFGHIJKLMNOP",
		"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJlc2lnbmF0dXJl",
		"Authorization: Bearer abcdef0123456789",
		"https://user:hunter2@example.invalid/repo.git",
		"--password=hunter2",
		"glpat-abcdefghijklmnopqrst",
		"xoxb-123456789012-abcdefghij",
	} {
		got := r.Argv([]string{"cmd", arg})
		if got[1] == arg || !strings.Contains(got[1], Redacted) {
			t.Errorf("argument %q was not redacted: %q", arg, got[1])
		}
	}
	for _, arg := range []string{"./...", "-run", "TestFoo", "main", "--short"} {
		if got := r.Argv([]string{"cmd", arg}); got[1] != arg {
			t.Errorf("ordinary argument %q was changed to %q", arg, got[1])
		}
	}
}

func TestRedactor_OperatorAdditions(t *testing.T) {
	r, err := NewRedactor([]string{`acme-[0-9]{6}`})
	if err != nil {
		t.Fatal(err)
	}
	if got := r.Argv([]string{"login", "acme-123456"}); got[1] != Redacted {
		t.Errorf("operator pattern not applied: %q", got)
	}
	if _, err := NewRedactor([]string{"("}); err == nil {
		t.Error("an invalid operator pattern must be refused")
	}
}
