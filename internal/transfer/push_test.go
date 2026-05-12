package transfer

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPushState_RoundtripMissingFile(t *testing.T) {
	dir := t.TempDir()
	s, err := loadPushState(dir)
	require.NoError(t, err)
	assert.Empty(t, s.lastFor("anyone", "main"))
}

func TestPushState_SetGetSave(t *testing.T) {
	dir := t.TempDir()
	s, _ := loadPushState(dir)

	s.setLast("alice", "main", "abc123")
	s.setLast("alice", "feature/foo", "def456")
	s.setLast("bob", "main", "ghi789")

	require.NoError(t, s.save(dir))

	// Roundtrip through disk.
	s2, err := loadPushState(dir)
	require.NoError(t, err)
	assert.Equal(t, "abc123", s2.lastFor("alice", "main"))
	assert.Equal(t, "def456", s2.lastFor("alice", "feature/foo"))
	assert.Equal(t, "ghi789", s2.lastFor("bob", "main"))
	assert.Empty(t, s2.lastFor("alice", "nope"))
	assert.Empty(t, s2.lastFor("charlie", "main"))
}

func TestPushState_TombstonedJSONIsForgiving(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, stateFile), []byte("not-json"), 0o600))
	// Should not error; just return empty state.
	s, err := loadPushState(dir)
	require.NoError(t, err)
	assert.Empty(t, s.lastFor("anyone", "main"))
}
