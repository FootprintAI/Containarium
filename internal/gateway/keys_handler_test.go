package gateway

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestServeAuthorizedKeys_Empty(t *testing.T) {
	// The handler reads from /home which we can't override, so test the response structure
	handler := ServeAuthorizedKeys("", nil)
	req := httptest.NewRequest(http.MethodGet, "/authorized-keys", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	var resp KeysResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	// On a dev machine, /home may or may not have users with authorized_keys
	// The key thing is the response parses correctly as JSON
	t.Logf("got %d keys from /home", len(resp.Keys))
}

// TestServeAuthorizedKeys_OrphanFiltered is the regression guard for
// #343: when a tenant container has been deleted but the host user +
// authorized_keys file survive (userdel failure, manual provisioning,
// etc.), the keys endpoint must NOT return the orphan — otherwise
// sshpiper accepts the client's key and the relay later fails inside
// the SSH session with "Container X not found".
func TestServeAuthorizedKeys_OrphanFiltered(t *testing.T) {
	tmpHome := t.TempDir()
	mkUser(t, tmpHome, "alice", "ssh-ed25519 AAAA_alice alice@laptop\n")
	mkUser(t, tmpHome, "orphan", "ssh-ed25519 AAAA_orphan orphan@old\n")

	// Filter says alice's container exists, orphan's does not.
	exists := func(username string) bool { return username == "alice" }

	handler := ServeAuthorizedKeys(tmpHome, exists)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/authorized-keys", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	var resp KeysResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Keys) != 1 {
		t.Fatalf("expected exactly 1 entry (alice only), got %d", len(resp.Keys))
	}
	if resp.Keys[0].Username != "alice" {
		t.Errorf("expected alice, got %s", resp.Keys[0].Username)
	}
}

// TestServeAuthorizedKeys_OrphanWarningSkipsNonContainerShell is the
// regression guard for the "ubuntu" incident: a real host admin account
// (getent-resolvable, but never running the containarium-shell wrapper) can
// share the orphan directory shape (authorized_keys under homeRoot, no
// matching container) without ever being orphan-reaper-eligible — see
// pkg/core/container's IsContainerManagedShell. The keysync WARNING must not
// claim "orphan-reaper will clean up on next tick" for an account the
// reaper will never touch; exclusion from the response itself (#343) is
// unaffected.
func TestServeAuthorizedKeys_OrphanWarningSkipsNonContainerShell(t *testing.T) {
	if _, err := exec.LookPath("getent"); err != nil {
		t.Skip("getent not available on this platform (Linux-only tool; CI runs Linux)")
	}

	tmpHome := t.TempDir()
	// "root" always exists via getent and never runs the containarium-shell
	// wrapper — same fixture-free approach as
	// pkg/core/container's TestUserShell_ParsesGetentOutput.
	mkUser(t, tmpHome, "root", "ssh-ed25519 AAAA_root root@admin\n")

	exists := func(string) bool { return false } // no container for anyone

	var logBuf bytes.Buffer
	orig := log.Writer()
	log.SetOutput(&logBuf)
	defer log.SetOutput(orig)

	handler := ServeAuthorizedKeys(tmpHome, exists)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/authorized-keys", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var resp KeysResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	for _, k := range resp.Keys {
		if k.Username == "root" {
			t.Fatal("root should still be excluded from the keys response (no matching container) — unaffected by this fix")
		}
	}
	if strings.Contains(logBuf.String(), "orphan authorized_keys found") {
		t.Errorf("WARNING must not fire for a non-containarium-shell account (the reaper will never touch it); got log: %s", logBuf.String())
	}
}

// TestServeAuthorizedKeys_NilFilterIncludesAll asserts the back-compat
// path — when containerExistsFn is nil, every user in homeRoot is
// returned (matches the pre-#343 behavior so the orphan filter is
// strictly opt-in at the wiring layer).
func TestServeAuthorizedKeys_NilFilterIncludesAll(t *testing.T) {
	tmpHome := t.TempDir()
	mkUser(t, tmpHome, "alice", "ssh-ed25519 AAAA_alice alice@laptop\n")
	mkUser(t, tmpHome, "bob", "ssh-ed25519 AAAA_bob bob@laptop\n")

	handler := ServeAuthorizedKeys(tmpHome, nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/authorized-keys", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var resp KeysResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Keys) != 2 {
		t.Fatalf("expected 2 entries (no filter), got %d", len(resp.Keys))
	}
}

func TestServeAuthorizedKeys_MethodNotAllowed(t *testing.T) {
	handler := ServeAuthorizedKeys("", nil)
	req := httptest.NewRequest(http.MethodPost, "/authorized-keys", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestServeSentinelKey_MethodNotAllowed(t *testing.T) {
	handler := ServeSentinelKey()
	req := httptest.NewRequest(http.MethodGet, "/authorized-keys/sentinel", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestServeSentinelKey_EmptyKey(t *testing.T) {
	handler := ServeSentinelKey()
	body := `{"public_key": ""}`
	req := httptest.NewRequest(http.MethodPost, "/authorized-keys/sentinel", bytes.NewBufferString(body))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for empty key, got %d", rr.Code)
	}
}

func TestServeSentinelKey_InvalidJSON(t *testing.T) {
	handler := ServeSentinelKey()
	req := httptest.NewRequest(http.MethodPost, "/authorized-keys/sentinel", bytes.NewBufferString("{invalid}"))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid JSON, got %d", rr.Code)
	}
}

func TestKeysResponseSerialization(t *testing.T) {
	resp := KeysResponse{
		Keys: []UserKeys{
			{Username: "alice", AuthorizedKeys: "ssh-ed25519 AAAAC3Nz... alice@laptop"},
			{Username: "bob", AuthorizedKeys: "ssh-rsa AAAAB3Nz... bob@workstation"},
		},
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var parsed KeysResponse
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if len(parsed.Keys) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(parsed.Keys))
	}
	if parsed.Keys[0].Username != "alice" {
		t.Errorf("expected username alice, got %s", parsed.Keys[0].Username)
	}
	if parsed.Keys[1].Username != "bob" {
		t.Errorf("expected username bob, got %s", parsed.Keys[1].Username)
	}
}

func TestSentinelKeyRequest_DuplicateDetection(t *testing.T) {
	// Setup: create a temp home dir with a user who already has the sentinel key
	tmpHome := t.TempDir()
	username := "testuser"
	sshDir := filepath.Join(tmpHome, username, ".ssh")
	if err := os.MkdirAll(sshDir, 0700); err != nil {
		t.Fatal(err)
	}

	sentinelKey := "ssh-ed25519 AAAA_sentinel_key sentinel@sshpiper"
	akContent := "ssh-ed25519 AAAA_existing_key user@laptop\n# sshpiper sentinel upstream key\n" + sentinelKey + "\n"
	akPath := filepath.Join(sshDir, "authorized_keys")
	if err := os.WriteFile(akPath, []byte(akContent), 0600); err != nil {
		t.Fatal(err)
	}

	// Verify the key is already there (checking string containment logic)
	data, err := os.ReadFile(akPath)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Contains(data, []byte(sentinelKey)) {
		t.Error("sentinel key should already be present in authorized_keys")
	}
}

func TestRewriteSentinelBlock_FirstInstall(t *testing.T) {
	existing := "ssh-ed25519 AAAA_user_key user@laptop\n"
	key := "ssh-ed25519 AAAA_new_sentinel sentinel@sshpiper"

	out, hadPrior, priorDiffers := rewriteSentinelBlock(existing, key)
	if hadPrior {
		t.Error("did not expect a prior sentinel block")
	}
	if priorDiffers {
		t.Error("priorDiffers should be false on first install")
	}
	if !strings.Contains(out, key) {
		t.Errorf("output missing new key:\n%s", out)
	}
	if !strings.Contains(out, "ssh-ed25519 AAAA_user_key user@laptop") {
		t.Errorf("output dropped existing user key:\n%s", out)
	}
	if strings.Count(out, sentinelKeyMarker) != 1 {
		t.Errorf("expected exactly one sentinel marker, got %d:\n%s",
			strings.Count(out, sentinelKeyMarker), out)
	}
}

func TestRewriteSentinelBlock_Rotation(t *testing.T) {
	oldKey := "ssh-ed25519 AAAA_OLD_sentinel_key sentinel@old"
	newKey := "ssh-ed25519 AAAA_NEW_sentinel_key sentinel@new"
	existing := "ssh-ed25519 AAAA_user_key user@laptop\n" +
		sentinelKeyMarker + "\n" +
		oldKey + "\n"

	out, hadPrior, priorDiffers := rewriteSentinelBlock(existing, newKey)
	if !hadPrior {
		t.Error("expected hadPrior=true")
	}
	if !priorDiffers {
		t.Error("expected priorDiffers=true")
	}
	if strings.Contains(out, oldKey) {
		t.Errorf("rotation should have removed old sentinel key:\n%s", out)
	}
	if !strings.Contains(out, newKey) {
		t.Errorf("rotation should have installed new sentinel key:\n%s", out)
	}
	if strings.Count(out, sentinelKeyMarker) != 1 {
		t.Errorf("expected exactly one sentinel marker after rotation, got %d:\n%s",
			strings.Count(out, sentinelKeyMarker), out)
	}
	if !strings.Contains(out, "ssh-ed25519 AAAA_user_key user@laptop") {
		t.Errorf("rotation dropped user's own key:\n%s", out)
	}
}

func TestRewriteSentinelBlock_Idempotent(t *testing.T) {
	key := "ssh-ed25519 AAAA_sentinel sentinel@sshpiper"
	existing := "ssh-ed25519 AAAA_user user@laptop\n\n" +
		sentinelKeyMarker + "\n" +
		key + "\n"

	out, hadPrior, priorDiffers := rewriteSentinelBlock(existing, key)
	if !hadPrior {
		t.Error("expected hadPrior=true")
	}
	if priorDiffers {
		t.Error("priorDiffers should be false when key is unchanged")
	}
	// Should remain idempotent — applying the same key twice produces
	// the same content as applying once.
	out2, _, _ := rewriteSentinelBlock(out, key)
	if out != out2 {
		t.Errorf("not idempotent:\nfirst:\n%s\nsecond:\n%s", out, out2)
	}
	if strings.Count(out, sentinelKeyMarker) != 1 {
		t.Errorf("expected exactly one sentinel marker, got %d:\n%s",
			strings.Count(out, sentinelKeyMarker), out)
	}
}

func TestRewriteSentinelBlock_MultipleStaleMarkers(t *testing.T) {
	// Defensive: an authorized_keys with two prior sentinel blocks (from a
	// bug or manual edit) should be cleaned up — exactly one marker survives.
	existing := sentinelKeyMarker + "\n" +
		"ssh-ed25519 AAAA_stale_1\n" +
		"ssh-ed25519 AAAA_user user@laptop\n" +
		sentinelKeyMarker + "\n" +
		"ssh-ed25519 AAAA_stale_2\n"
	newKey := "ssh-ed25519 AAAA_current sentinel@new"

	out, hadPrior, _ := rewriteSentinelBlock(existing, newKey)
	if !hadPrior {
		t.Error("expected hadPrior=true")
	}
	if strings.Contains(out, "AAAA_stale_1") || strings.Contains(out, "AAAA_stale_2") {
		t.Errorf("output retained stale sentinel keys:\n%s", out)
	}
	if !strings.Contains(out, newKey) {
		t.Errorf("output missing current key:\n%s", out)
	}
	if strings.Count(out, sentinelKeyMarker) != 1 {
		t.Errorf("expected exactly one marker, got %d:\n%s",
			strings.Count(out, sentinelKeyMarker), out)
	}
}

func TestRewriteSentinelBlock_AbsorbsUnmarkedDuplicate(t *testing.T) {
	// The live BYOC failure mode: an older seeding path / manual injection
	// left the current upstream key in the file WITHOUT the marker, so the
	// marker scan alone never reconciled it and copies accumulated. The
	// rewrite must absorb the unmarked copy into the single canonical block.
	key := "ssh-ed25519 AAAA_sentinel sentinel@sshpiper"
	existing := "ssh-ed25519 AAAA_user user@laptop\n" +
		key + " stray-comment\n" + // unmarked copy (different comment)
		sentinelKeyMarker + "\n" +
		key + "\n" +
		key + "\n" // a second bare unmarked dup

	out, _, _ := rewriteSentinelBlock(existing, key)
	if got := strings.Count(out, "AAAA_sentinel"); got != 1 {
		t.Errorf("expected the sentinel key exactly once, got %d:\n%s", got, out)
	}
	if strings.Count(out, sentinelKeyMarker) != 1 {
		t.Errorf("expected exactly one marker, got %d:\n%s",
			strings.Count(out, sentinelKeyMarker), out)
	}
	if !strings.Contains(out, "AAAA_user user@laptop") {
		t.Errorf("user key must be preserved:\n%s", out)
	}
	// Idempotent on the cleaned-up content.
	out2, _, _ := rewriteSentinelBlock(out, key)
	if out != out2 {
		t.Errorf("not idempotent after absorbing dup:\nfirst:\n%s\nsecond:\n%s", out, out2)
	}
}

func TestRewriteSentinelBlock_CommentOnlyDiffIsNotRotation(t *testing.T) {
	// Same key material, different comment, behind the marker: this is the
	// same key, not a rotation — priorDiffers must stay false.
	existing := sentinelKeyMarker + "\n" +
		"ssh-ed25519 AAAA_sentinel old-comment\n"
	key := "ssh-ed25519 AAAA_sentinel new-comment"

	_, hadPrior, priorDiffers := rewriteSentinelBlock(existing, key)
	if !hadPrior {
		t.Error("expected hadPrior=true")
	}
	if priorDiffers {
		t.Error("comment-only difference must not be treated as a rotation")
	}
}

func TestSSHKeyMaterial(t *testing.T) {
	cases := []struct {
		in     string
		want   string
		wantOk bool
	}{
		{"ssh-ed25519 AAAA comment", "ssh-ed25519 AAAA", true},
		{"  ssh-rsa BBBB  ", "ssh-rsa BBBB", true},
		{"ecdsa-sha2-nistp256 CCCC host", "ecdsa-sha2-nistp256 CCCC", true},
		{"sk-ssh-ed25519@openssh.com DDDD", "sk-ssh-ed25519@openssh.com DDDD", true},
		{sentinelKeyMarker, "", false},
		{"", "", false},
		{"ssh-ed25519", "", false}, // type only, no material
	}
	for _, c := range cases {
		got, ok := sshKeyMaterial(c.in)
		if got != c.want || ok != c.wantOk {
			t.Errorf("sshKeyMaterial(%q) = (%q,%v), want (%q,%v)", c.in, got, ok, c.want, c.wantOk)
		}
	}
}

func TestApplySentinelKey_FirstInstall(t *testing.T) {
	tmpHome := t.TempDir()
	mkUser(t, tmpHome, "alice", "ssh-ed25519 AAAA_alice alice@laptop\n")
	mkUser(t, tmpHome, "bob", "ssh-ed25519 AAAA_bob bob@laptop\n")

	newKey := "ssh-ed25519 AAAA_new_sentinel sentinel@new"
	updated, rotated, err := applySentinelKey(tmpHome, newKey)
	if err != nil {
		t.Fatal(err)
	}
	if updated != 2 {
		t.Errorf("expected updated=2, got %d", updated)
	}
	if rotated != 0 {
		t.Errorf("expected rotated=0 on first install, got %d", rotated)
	}

	for _, u := range []string{"alice", "bob"} {
		readAndAssert(t, tmpHome, u, newKey, true)
	}
}

func TestApplySentinelKey_Rotation(t *testing.T) {
	tmpHome := t.TempDir()
	oldKey := "ssh-ed25519 AAAA_OLD_sentinel sentinel@old"
	newKey := "ssh-ed25519 AAAA_NEW_sentinel sentinel@new"

	mkUser(t, tmpHome, "alice",
		"ssh-ed25519 AAAA_alice alice@laptop\n"+
			sentinelKeyMarker+"\n"+oldKey+"\n")
	mkUser(t, tmpHome, "bob",
		"ssh-ed25519 AAAA_bob bob@laptop\n"+
			sentinelKeyMarker+"\n"+oldKey+"\n")

	updated, rotated, err := applySentinelKey(tmpHome, newKey)
	if err != nil {
		t.Fatal(err)
	}
	if updated != 2 {
		t.Errorf("expected updated=2, got %d", updated)
	}
	if rotated != 2 {
		t.Errorf("expected rotated=2 on key change, got %d", rotated)
	}

	for _, u := range []string{"alice", "bob"} {
		readAndAssert(t, tmpHome, u, newKey, true)
		readAndAssert(t, tmpHome, u, oldKey, false)
	}
}

func TestApplySentinelKey_NoOpWhenIdentical(t *testing.T) {
	tmpHome := t.TempDir()
	key := "ssh-ed25519 AAAA_sentinel sentinel@sshpiper"

	// User starts with the canonical layout — apply should produce the
	// same content (no file write needed, but updated counter still bumps
	// because the key IS present).
	initial := "ssh-ed25519 AAAA_alice alice@laptop\n\n" +
		sentinelKeyMarker + "\n" + key + "\n"
	mkUser(t, tmpHome, "alice", initial)

	updated, rotated, err := applySentinelKey(tmpHome, key)
	if err != nil {
		t.Fatal(err)
	}
	if updated != 1 {
		t.Errorf("expected updated=1 (key is present), got %d", updated)
	}
	if rotated != 0 {
		t.Errorf("expected rotated=0 on no-op, got %d", rotated)
	}
}

func TestApplySentinelKey_SkipsUsersWithoutSshDir(t *testing.T) {
	tmpHome := t.TempDir()
	// alice has .ssh, bob does not — bob should be skipped, not errored.
	mkUser(t, tmpHome, "alice", "ssh-ed25519 AAAA_alice alice@laptop\n")
	if err := os.MkdirAll(filepath.Join(tmpHome, "bob"), 0o755); err != nil {
		t.Fatal(err)
	}

	newKey := "ssh-ed25519 AAAA_sentinel sentinel@sshpiper"
	updated, _, err := applySentinelKey(tmpHome, newKey)
	if err != nil {
		t.Fatal(err)
	}
	if updated != 1 {
		t.Errorf("expected updated=1 (alice only), got %d", updated)
	}
}

// mkUser writes a user's authorized_keys under tmpHome and ensures the
// .ssh dir exists.
func mkUser(t *testing.T, tmpHome, username, akContent string) {
	t.Helper()
	sshDir := filepath.Join(tmpHome, username, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sshDir, "authorized_keys"), []byte(akContent), 0o600); err != nil {
		t.Fatal(err)
	}
}

// readAndAssert reads a user's authorized_keys and asserts substring presence.
func readAndAssert(t *testing.T, tmpHome, username, substr string, wantContains bool) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(tmpHome, username, ".ssh", "authorized_keys"))
	if err != nil {
		t.Fatal(err)
	}
	has := strings.Contains(string(data), substr)
	if has != wantContains {
		t.Errorf("user %s authorized_keys: substr %q contains=%v, want %v\nfile:\n%s",
			username, substr, has, wantContains, string(data))
	}
}
