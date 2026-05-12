package transfer

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildChangedTar_PreservesModeAndContent(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "hello.txt"), []byte("hello world"), 0o644))
	require.NoError(t, os.MkdirAll(filepath.Join(root, "bin"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "bin", "run.sh"), []byte("#!/bin/sh\n"), 0o755))

	var buf bytes.Buffer
	n, err := buildChangedTar(root, []string{"hello.txt", "bin/run.sh"}, &buf)
	require.NoError(t, err)
	assert.Greater(t, n, int64(0))

	gz, err := gzip.NewReader(&buf)
	require.NoError(t, err)
	tr := tar.NewReader(gz)

	got := map[string]struct {
		mode    int64
		content []byte
	}{}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		body, _ := io.ReadAll(tr)
		got[hdr.Name] = struct {
			mode    int64
			content []byte
		}{mode: hdr.Mode, content: body}
	}

	require.Len(t, got, 2)
	assert.Equal(t, "hello world", string(got["hello.txt"].content))
	assert.Equal(t, int64(0o644), got["hello.txt"].mode&0o777)
	assert.Equal(t, int64(0o755), got["bin/run.sh"].mode&0o777, "executable bit preserved")
}

func TestShQuote(t *testing.T) {
	cases := []struct{ in, want string }{
		{"simple", "'simple'"},
		{"with spaces", "'with spaces'"},
		{"has'quote", `'has'\''quote'`},
		{"", "''"},
	}
	for _, c := range cases {
		assert.Equal(t, c.want, shQuote(c.in))
	}
}

func TestConditional(t *testing.T) {
	assert.Equal(t, "yes", conditional(true, "yes"))
	assert.Equal(t, "", conditional(false, "yes"))
}
