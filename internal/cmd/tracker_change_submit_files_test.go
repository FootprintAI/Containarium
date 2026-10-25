package cmd

import (
	"errors"
	"testing"
)

func TestParseChangeFileFlags(t *testing.T) {
	read := func(p string) ([]byte, error) {
		if p == "missing" {
			return nil, errors.New("no such file")
		}
		return []byte("content of " + p), nil
	}
	files, err := parseChangeFileFlags([]string{"docs/a.md=./a.md", "b=c=d"}, read)
	if err != nil {
		t.Fatalf("parseChangeFileFlags: %v", err)
	}
	if len(files) != 2 || files[0].GetPath() != "docs/a.md" || files[0].GetContent() != "content of ./a.md" {
		t.Fatalf("files = %v", files)
	}
	// Only the first "=" splits: the local path may itself contain one.
	if files[1].GetPath() != "b" || files[1].GetContent() != "content of c=d" {
		t.Errorf("files[1] = %v, want path b read from c=d", files[1])
	}
	for _, bad := range []string{"noequals", "=local", "repo=", "x=missing"} {
		if _, err := parseChangeFileFlags([]string{bad}, read); err == nil {
			t.Errorf("parseChangeFileFlags(%q) = nil error, want one", bad)
		}
	}
}
