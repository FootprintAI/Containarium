package transfer

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWalkLocal_HashesAndModesContent(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "a.txt"), []byte("hello"), 0o644))
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "sub"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "sub", "b.sh"), []byte("#!/bin/sh\necho hi\n"), 0o755))

	m, err := walkLocal(dir, nil)
	require.NoError(t, err)
	require.Len(t, m.entries, 2)

	a := m.entries["a.txt"]
	assert.Equal(t, "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", a.Hash)
	assert.Equal(t, uint32(0o644), a.Mode)

	b := m.entries["sub/b.sh"]
	assert.Equal(t, uint32(0o755), b.Mode, "executable bit preserved")
}

func TestWalkLocal_ExcludeBySubstring(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "node_modules", "deep"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "node_modules", "deep", "x.js"), []byte("dont care"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "keep.txt"), []byte("keep"), 0o644))

	m, err := walkLocal(dir, []string{"node_modules/"})
	require.NoError(t, err)
	require.Len(t, m.entries, 1)
	_, kept := m.entries["keep.txt"]
	assert.True(t, kept)
}

func TestWalkLocal_SkipsSymlinks(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "real.txt"), []byte("real"), 0o644))
	require.NoError(t, os.Symlink("real.txt", filepath.Join(dir, "link.txt")))

	m, err := walkLocal(dir, nil)
	require.NoError(t, err)
	// Symlink should be skipped; only real.txt appears.
	_, hasReal := m.entries["real.txt"]
	_, hasLink := m.entries["link.txt"]
	assert.True(t, hasReal)
	assert.False(t, hasLink, "symlink should be skipped in v1")
}

func TestDiff_AddModifyDelete(t *testing.T) {
	local := newManifest()
	local.entries["new.txt"] = fileEntry{Path: "new.txt", Hash: "h1", Mode: 0o644}
	local.entries["common.txt"] = fileEntry{Path: "common.txt", Hash: "hC", Mode: 0o644}
	local.entries["changed.txt"] = fileEntry{Path: "changed.txt", Hash: "newH", Mode: 0o644}
	local.entries["mode-changed.sh"] = fileEntry{Path: "mode-changed.sh", Hash: "hM", Mode: 0o755}

	remote := newManifest()
	remote.entries["common.txt"] = fileEntry{Path: "common.txt", Hash: "hC", Mode: 0o644}
	remote.entries["changed.txt"] = fileEntry{Path: "changed.txt", Hash: "oldH", Mode: 0o644}
	remote.entries["mode-changed.sh"] = fileEntry{Path: "mode-changed.sh", Hash: "hM", Mode: 0o644}
	remote.entries["stale.txt"] = fileEntry{Path: "stale.txt", Hash: "hS", Mode: 0o644}

	d := local.diff(remote)
	assert.Equal(t, []string{"changed.txt", "mode-changed.sh", "new.txt"}, d.ToAddOrModify)
	assert.Equal(t, []string{"stale.txt"}, d.ToDelete)
}

func TestParseRemoteManifest_Roundtrip(t *testing.T) {
	in := strings.NewReader(strings.Join([]string{
		"a1b2 644 hello.txt",
		"c3d4 755 bin/run.sh",
		"",                         // blank line — skip
		"malformed-line-no-spaces", // skip
		"e5f6 600 with spaces/in/path.txt",
	}, "\n"))

	m, err := parseRemoteManifest(in)
	require.NoError(t, err)
	require.Len(t, m.entries, 3)
	assert.Equal(t, "a1b2", m.entries["hello.txt"].Hash)
	assert.Equal(t, uint32(0o755), m.entries["bin/run.sh"].Mode)
	assert.Equal(t, "e5f6", m.entries["with spaces/in/path.txt"].Hash)
}

func TestMatchesAny(t *testing.T) {
	assert.True(t, matchesAny("foo/node_modules/dep/x.js", []string{"node_modules/"}))
	assert.False(t, matchesAny("keep.txt", []string{"node_modules/", "__pycache__/"}))
	assert.False(t, matchesAny("anything", nil))
	assert.False(t, matchesAny("anything", []string{""}))
}
